// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Wi-Fi association diagnostics (round 1.3.7, CONFIG_TINYLINK_WIFI_DIAG).
// Built only with the option (main/CMakeLists.txt), which also links the
// supplicant's EAPOL path through the __wrap_ functions below
// (-Wl,--wrap: the references from esp_wpa_main.c / wpa.c are rewritten,
// the IDF sources stay untouched):
//
//   wpa_sm_rx_eapol    every EAPOL frame the driver hands to wpa.c, with
//                      what wpa.c returned (1 processed, 0 not a key
//                      frame, -1 dropped: replay counter, descriptor
//                      version, MIC, …)
//   wpa_ether_send     every M2 / M4 / group 2/2 wpa.c sends
//   eapol_txcb         whether the AP acknowledged it (MAC-level ACK)
//   esp_wifi_internal_issue_disconnect
//                      a disconnect raised by the supplicant itself — in
//                      this configuration only wpa.c's "EAPOL1 received
//                      for 4 times, sending deauth" (MAX_EAPOL_RETRIES 3;
//                      its wpa_printf is compiled out)
//
// The question it answers (wifi_hint.h): after the AP's association
// comeback the 4-way handshake takes 10–30 ms, exactly 2.0 s, or dies at
// exactly 3.0 s with a locally raised reason 15. If M1 arrives every 1.0 s
// and each M2 is ACKed but never answered by M3, the AP is ignoring our
// M2 (its old PMF association not yet gone); if M1 reaches wpa.c only
// after ~2 s, it was lost or never sent — the sniffer
// (CONFIG_TINYLINK_WIFI_DIAG_SNIFF) then tells the two apart, and shows a
// M1 encrypted with a stale key as a protected data frame.
//
// The hooks and the sniffer run on the Wi-Fi task: they only copy 16 B
// into a ring under a spinlock. wifi_diag_flush prints from the event
// handler (sys_evt), so the console never delays a M2.

#include "wifi_diag.h"

#if CONFIG_TINYLINK_WIFI_DIAG

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"

static const char *TAG = "wifi_diag";

enum {
    EV_RX = 1,        /* EAPOL into wpa.c */
    EV_TX,            /* EAPOL out of wpa.c */
    EV_TXDONE,        /* its TX status */
    EV_SUPP_DISC,     /* wpa.c raised a disconnect */
    EV_APP,           /* wifi_diag_note */
    EV_AIR_EAPOL,     /* sniffed: unprotected EAPOL to us */
    EV_AIR_PROT,      /* sniffed: protected data frame to us */
    EV_AIR_MGMT,      /* sniffed: management frame to us */
};

typedef struct {
    uint32_t t_ms;
    uint8_t  ev;
    uint8_t  msg;      /* 1..4 = M1..M4, 5 = G1, 6 = G2; app event; mgmt subtype */
    uint16_t info;     /* key_info; reason / status; app a */
    uint32_t rc;       /* replay counter (low 32 bits) */
    int16_t  ret;      /* wpa.c return / tx failure / RSSI / app b */
    uint16_t seq;      /* nonce[0] (wpa.c side) or sequence control | retry << 15 (air) */
} diag_ev_t;

#define DIAG_N 64
static diag_ev_t    s_ev[DIAG_N];
static uint32_t     s_head, s_tail, s_lost;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

static inline uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static void push(const diag_ev_t *e)
{
    portENTER_CRITICAL_SAFE(&s_mux);
    if (s_head - s_tail < DIAG_N) {
        s_ev[s_head % DIAG_N] = *e;
        s_head++;
    } else {
        s_lost++;
    }
    portEXIT_CRITICAL_SAFE(&s_mux);
}

/* key_info → message: pairwise ACK = M1 / M3 (MIC), pairwise without ACK
 * = M2 / M4 (Secure), group = 1/2 (ACK) or 2/2. */
static uint8_t key_msg(uint16_t info)
{
    const bool pairwise = info & 0x0008, ack = info & 0x0080, mic = info & 0x0100,
               secure = info & 0x0200;
    if (pairwise) return ack ? (mic ? 3 : 1) : (secure ? 4 : 2);
    return ack ? 5 : 6;
}

/* An 802.1X frame from its header: version, type (3 = EAPOL-Key),
 * length, then descriptor type, key_info, key_length, replay counter (8),
 * key nonce (32). */
#define KEY_MIN (4 + 1 + 2 + 2 + 8 + 1)

static void key_fields(diag_ev_t *e, const uint8_t *x, size_t n)
{
    if (x == NULL || n < KEY_MIN || x[1] != 3) return;
    const uint8_t *k = x + 4;
    e->info = (uint16_t)((k[1] << 8) | k[2]);
    e->msg  = key_msg(e->info);
    e->rc   = ((uint32_t)k[9] << 24) | ((uint32_t)k[10] << 16) | ((uint32_t)k[11] << 8) | k[12];
    e->seq  = k[13];
}

/* ---- The wrapped supplicant functions -------------------------------- */

int  __real_wpa_sm_rx_eapol(uint8_t *src_addr, uint8_t *buf, uint32_t len);
int  __real_wpa_ether_send(void *ctx, const uint8_t *dest, uint16_t proto,
                           const uint8_t *data, size_t data_len);
void __real_eapol_txcb(uint8_t *eapol_payload, size_t len, bool tx_failure);
esp_err_t __real_esp_wifi_internal_issue_disconnect(uint8_t reason_code);

int __wrap_wpa_sm_rx_eapol(uint8_t *src_addr, uint8_t *buf, uint32_t len)
{
    diag_ev_t e = { .t_ms = now_ms(), .ev = EV_RX };
    key_fields(&e, buf, len);              /* before: wpa.c decrypts key data in place */
    const int r = __real_wpa_sm_rx_eapol(src_addr, buf, len);
    e.ret = (int16_t)r;
    push(&e);
    return r;
}

int __wrap_wpa_ether_send(void *ctx, const uint8_t *dest, uint16_t proto,
                          const uint8_t *data, size_t data_len)
{
    diag_ev_t e = { .t_ms = now_ms(), .ev = EV_TX };
    key_fields(&e, data, data_len);
    const int r = __real_wpa_ether_send(ctx, dest, proto, data, data_len);
    e.ret = (int16_t)r;
    push(&e);
    return r;
}

void __wrap_eapol_txcb(uint8_t *eapol_payload, size_t len, bool tx_failure)
{
    diag_ev_t e = { .t_ms = now_ms(), .ev = EV_TXDONE, .ret = tx_failure ? 1 : 0 };
    key_fields(&e, eapol_payload, len);
    push(&e);
    __real_eapol_txcb(eapol_payload, len, tx_failure);
}

esp_err_t __wrap_esp_wifi_internal_issue_disconnect(uint8_t reason_code)
{
    const diag_ev_t e = { .t_ms = now_ms(), .ev = EV_SUPP_DISC, .info = reason_code };
    push(&e);
    return __real_esp_wifi_internal_issue_disconnect(reason_code);
}

/* ---- Application events ---------------------------------------------- */

void wifi_diag_note(wifi_diag_event_t ev, uint16_t a, int16_t b)
{
    const diag_ev_t e = { .t_ms = now_ms(), .ev = EV_APP, .msg = (uint8_t)ev,
                          .info = a, .ret = b };
    push(&e);
}

/* ---- Sniffer (CONFIG_TINYLINK_WIFI_DIAG_SNIFF) ------------------------ */

#if CONFIG_TINYLINK_WIFI_DIAG_SNIFF
static uint8_t s_own_mac[6];
static bool    s_sniffing;

/* Frames whose addr1 is the station: the AP's side of the association. */
static void sniff_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = p->payload;
    const size_t   n = p->rx_ctrl.sig_len >= 4 ? p->rx_ctrl.sig_len - 4 : 0;   /* FCS */
    if (n < 24 || memcmp(f + 4, s_own_mac, 6) != 0) return;
    diag_ev_t e = { .t_ms = now_ms(), .ret = (int16_t)p->rx_ctrl.rssi,
                    .seq = (uint16_t)(((f[23] << 8) | f[22]) >> 4) |
                           (uint16_t)((f[1] & 0x08) ? 0x8000u : 0u) };
    const bool prot = f[1] & 0x40;
    if (type == WIFI_PKT_DATA) {
        size_t h = 24;
        if ((f[1] & 0x03) == 0x03) h += 6;          /* four addresses */
        if (f[0] & 0x80) h += 2;                     /* QoS */
        if (prot) {
            e.ev   = EV_AIR_PROT;
            e.info = (uint16_t)n;
            push(&e);
            return;
        }
        if (n >= h + 8 + KEY_MIN && f[h] == 0xAA && f[h + 1] == 0xAA &&
            f[h + 6] == 0x88 && f[h + 7] == 0x8E) {
            e.ev = EV_AIR_EAPOL;
            const uint16_t seq = e.seq;
            key_fields(&e, f + h + 8, n - h - 8);
            e.seq = seq;
            push(&e);
        }
        return;                                      /* DHCP, ARP, … */
    }
    const uint8_t st = f[0] & 0xF0;
    if (st == 0x50 || st == 0x80) return;            /* probe response, beacon */
    e.ev  = EV_AIR_MGMT;
    e.msg = st;
    const uint8_t *body = f + 24;
    const size_t   bn   = n - 24;
    if (prot) {
        e.info = 0xFFFF;                             /* robust action (SA Query) / protected deauth */
    } else if (st == 0xB0 && bn >= 6) {              /* auth: status */
        e.info = (uint16_t)(body[4] | (body[5] << 8));
    } else if ((st == 0x10 || st == 0x30) && bn >= 4) {   /* (re)assoc response: status */
        e.info = (uint16_t)(body[2] | (body[3] << 8));
    } else if ((st == 0xC0 || st == 0xA0) && bn >= 2) {   /* deauth / disassoc: reason */
        e.info = (uint16_t)(body[0] | (body[1] << 8));
    } else if (st == 0xD0 && bn >= 1) {              /* action: category */
        e.info = body[0];
    }
    push(&e);
}
#endif /* CONFIG_TINYLINK_WIFI_DIAG_SNIFF */

void wifi_diag_start(void)
{
#if !CONFIG_TINYLINK_WIFI_DIAG_SNIFF
    ESP_LOGI(TAG, "EAPOL timeline on");
#else
    ESP_LOGI(TAG, "EAPOL timeline on, sniffing frames to us until got-ip");
    const wifi_promiscuous_filter_t flt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_err_t err = esp_wifi_get_mac(WIFI_IF_STA, s_own_mac);
    if (err == ESP_OK) err = esp_wifi_set_promiscuous_filter(&flt);
    if (err == ESP_OK) err = esp_wifi_set_promiscuous_rx_cb(sniff_cb);
    if (err == ESP_OK) err = esp_wifi_set_promiscuous(true);
    s_sniffing = err == ESP_OK;
    if (!s_sniffing) ESP_LOGW(TAG, "sniffer not started: 0x%x", err);
#endif
}

/* ---- Printing --------------------------------------------------------- */

static const char *const k_msg[] = { "?", "M1", "M2", "M3", "M4", "G1", "G2" };

static const char *mgmt_name(uint8_t st)
{
    switch (st) {
    case 0x00: return "assoc-req";
    case 0x10: return "assoc-resp";
    case 0x30: return "reassoc-resp";
    case 0xA0: return "disassoc";
    case 0xB0: return "auth";
    case 0xC0: return "deauth";
    case 0xD0: return "action";
    default:   return "mgmt";
    }
}

static void print_one(const diag_ev_t *e)
{
    const char *m = k_msg[e->msg <= 6 ? e->msg : 0];
    switch (e->ev) {
    case EV_RX:
        ESP_LOGI(TAG, "t=%u rx %s rc=%u info=0x%04x nonce=%02x -> %d (1 taken, -1 dropped by wpa.c)",
                 (unsigned)e->t_ms, m, (unsigned)e->rc, e->info, e->seq, e->ret);
        break;
    case EV_TX:
        ESP_LOGI(TAG, "t=%u tx %s rc=%u info=0x%04x -> %d", (unsigned)e->t_ms, m,
                 (unsigned)e->rc, e->info, e->ret);
        break;
    case EV_TXDONE:
        ESP_LOGI(TAG, "t=%u txdone %s rc=%u %s", (unsigned)e->t_ms, m, (unsigned)e->rc,
                 e->ret ? "FAIL (no ACK)" : "ok");
        break;
    case EV_SUPP_DISC:
        ESP_LOGI(TAG, "t=%u supplicant disconnect, reason %u", (unsigned)e->t_ms, e->info);
        break;
    case EV_APP:
        switch (e->msg) {
        case WIFI_DIAG_CONNECTED:
            ESP_LOGI(TAG, "t=%u connected, channel %u", (unsigned)e->t_ms, e->info);
            break;
        case WIFI_DIAG_DISCONNECTED:
            ESP_LOGI(TAG, "t=%u disconnected, reason %u, rssi %d", (unsigned)e->t_ms, e->info, e->ret);
            break;
        case WIFI_DIAG_GOT_IP:
            ESP_LOGI(TAG, "t=%u got ip", (unsigned)e->t_ms);
            break;
        case WIFI_DIAG_RETRY:
            ESP_LOGI(TAG, "t=%u retry in %d ms, channel %u first", (unsigned)e->t_ms, e->ret, e->info);
            break;
        default:
            break;
        }
        break;
    case EV_AIR_EAPOL:
        ESP_LOGI(TAG, "t=%u air %s rc=%u seq=%u%s rssi %d", (unsigned)e->t_ms, m, (unsigned)e->rc,
                 e->seq & 0x0FFFu, (e->seq & 0x8000u) ? " retry" : "", e->ret);
        break;
    case EV_AIR_PROT:
        ESP_LOGI(TAG, "t=%u air protected data len=%u seq=%u%s rssi %d", (unsigned)e->t_ms, e->info,
                 e->seq & 0x0FFFu, (e->seq & 0x8000u) ? " retry" : "", e->ret);
        break;
    case EV_AIR_MGMT:
        ESP_LOGI(TAG, "t=%u air %s %s%u seq=%u%s rssi %d", (unsigned)e->t_ms, mgmt_name(e->msg),
                 e->info == 0xFFFF ? "protected " : "", e->info == 0xFFFF ? 0u : e->info,
                 e->seq & 0x0FFFu, (e->seq & 0x8000u) ? " retry" : "", e->ret);
        break;
    default:
        break;
    }
}

void wifi_diag_flush(void)
{
    bool got_ip = false;
    for (;;) {
        diag_ev_t e;
        bool have;
        portENTER_CRITICAL(&s_mux);
        have = s_tail != s_head;
        if (have) e = s_ev[s_tail++ % DIAG_N];
        portEXIT_CRITICAL(&s_mux);
        if (!have) break;
        got_ip |= e.ev == EV_APP && e.msg == WIFI_DIAG_GOT_IP;
        print_one(&e);
    }
    portENTER_CRITICAL(&s_mux);
    const uint32_t lost = s_lost;
    s_lost = 0;
    portEXIT_CRITICAL(&s_mux);
    if (lost > 0) ESP_LOGW(TAG, "%u records lost (ring full)", (unsigned)lost);
#if CONFIG_TINYLINK_WIFI_DIAG_SNIFF
    if (got_ip && s_sniffing) {
        s_sniffing = false;
        (void)esp_wifi_set_promiscuous(false);
        ESP_LOGI(TAG, "sniffer off");
    }
#else
    (void)got_ip;
#endif
}

#endif /* CONFIG_TINYLINK_WIFI_DIAG */
