// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The servers' last-known addresses (tl_addr.h, round 1.3.5): IPv4
// literals as the DERP map carries them, the two NVS records (home DERP
// node, control address) and their validation on load, the record a
// netmap names and what it changes, the DNS-free STUN target, and the
// write-only-on-change rule over a fake NVS that counts flash writes —
// across simulated reboots.

#include <stdio.h>
#include <string.h>

#include "tl_addr.h"

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static int ip_is(const uint8_t ip[4], int a, int b, int c, int d)
{
    return ip[0] == a && ip[1] == b && ip[2] == c && ip[3] == d;
}

/* ---- IPv4 literals --------------------------------------------------- */

static int parses(const char *s, int a, int b, int c, int d)
{
    uint8_t ip[4] = { 9, 9, 9, 9 };
    return tl_ipv4_parse(s, strlen(s), ip) && ip_is(ip, a, b, c, d);
}

static int rejects(const char *s)
{
    uint8_t ip[4] = { 9, 9, 9, 9 };
    return !tl_ipv4_parse(s, strlen(s), ip) && ip_is(ip, 9, 9, 9, 9);   /* untouched */
}

static void test_ipv4(void)
{
    check("ipv4/dotted-quad", parses("203.0.113.7", 203, 0, 113, 7));
    check("ipv4/edges", parses("0.0.0.0", 0, 0, 0, 0) && parses("255.255.255.255", 255, 255, 255, 255));
    check("ipv4/zero-fields", parses("10.0.0.1", 10, 0, 0, 1));
    static const char *const bad[] = {
        "", "none", "203.0.113", "203.0.113.7.", ".203.0.113.7", "203.0.113.7.1",
        "203.0.113.256", "203.0.113.07", "00.1.2.3", "203.0.113.0007", "1234.1.1.1",
        "203.0..7", "203.0.113.7:443", " 203.0.113.7", "203.0.113.7 ", "+1.2.3.4",
        "-1.2.3.4", "0x7f.0.0.1", "2001:db8::7", "::ffff:203.0.113.7", "derp16b.tailscale.com",
    };
    int all = 1;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (!rejects(bad[i])) {
            printf("  accepted: '%s'\n", bad[i]);
            all = 0;
        }
    }
    check("ipv4/rejects-21-non-literals", all);
    /* Exactly n bytes: a literal inside a longer JSON token is not one. */
    uint8_t ip[4];
    check("ipv4/length-bounded", tl_ipv4_parse("203.0.113.7\",", 11, ip) && ip_is(ip, 203, 0, 113, 7) &&
                                 !tl_ipv4_parse("203.0.113.7\",", 12, ip));

    static const uint8_t ok1[4] = { 203, 0, 113, 7 }, ok2[4] = { 192, 168, 1, 10 },
                         ok3[4] = { 223, 255, 255, 254 }, z[4] = { 0, 0, 0, 0 },
                         z8[4] = { 0, 1, 2, 3 }, lo[4] = { 127, 0, 0, 1 },
                         mc[4] = { 224, 0, 0, 1 }, bc[4] = { 255, 255, 255, 255 },
                         rs[4] = { 240, 0, 0, 1 };
    check("ipv4/usable-unicast-and-private",
          tl_ipv4_usable(ok1) && tl_ipv4_usable(ok2) && tl_ipv4_usable(ok3));
    check("ipv4/unusable-none-this-loop-multi-bcast",
          !tl_ipv4_usable(z) && !tl_ipv4_usable(z8) && !tl_ipv4_usable(lo) &&
          !tl_ipv4_usable(mc) && !tl_ipv4_usable(bc) && !tl_ipv4_usable(rs) &&
          !tl_ipv4_usable(NULL));
    char s1[TL_IPV4_STRLEN], s2[TL_IPV4_STRLEN];
    tl_ipv4_str(ok1, s1);
    tl_ipv4_str(bc, s2);
    check("ipv4/str", strcmp(s1, "203.0.113.7") == 0 && strcmp(s2, "255.255.255.255") == 0);
}

static void test_stun_port(void)
{
    check("stunport/absent-zero-is-3478", tl_stun_port_parse("0", 1) == 3478);
    check("stunport/given", tl_stun_port_parse("3479", 4) == 3479 &&
                            tl_stun_port_parse("65535", 5) == 65535 && tl_stun_port_parse("1", 1) == 1);
    check("stunport/off-or-invalid",
          tl_stun_port_parse("-1", 2) == 0 && tl_stun_port_parse("65536", 5) == 0 &&
          tl_stun_port_parse("3478.0", 6) == 0 && tl_stun_port_parse("1e3", 3) == 0 &&
          tl_stun_port_parse("true", 4) == 0 && tl_stun_port_parse("", 0) == 0 &&
          tl_stun_port_parse("9999999", 7) == 0);
}

static void test_host(void)
{
    check("host/names", tl_host_ok("derp16b.tailscale.com", 21) &&
                        tl_host_ok("controlplane.tailscale.com", 26) && tl_host_ok("a", 1) &&
                        tl_host_ok("hs-1.LAN", 8));
    char h63[64];
    memset(h63, 'a', 63);
    h63[63] = '\0';
    check("host/63-ok-64-not", tl_host_ok(h63, 63) && !tl_host_ok(h63, 64));
    check("host/no-crlf-space-slash-colon-nul",
          !tl_host_ok("derp\r\nX: y", 10) && !tl_host_ok("derp 16", 7) &&
          !tl_host_ok("derp/16", 7) && !tl_host_ok("derp:443", 8) &&
          !tl_host_ok("de\0rp", 5) && !tl_host_ok("", 0) && !tl_host_ok(NULL, 3));
}

/* ---- Records ---------------------------------------------------------- */

static tl_derp_addr_t derp_rec(const char *host, int a, int b, int c, int d, uint16_t stun)
{
    tl_derp_addr_t r;
    memset(&r, 0, sizeof(r));
    r.region = 16;
    r.stun_port = stun;
    r.ipv4[0] = (uint8_t)a; r.ipv4[1] = (uint8_t)b; r.ipv4[2] = (uint8_t)c; r.ipv4[3] = (uint8_t)d;
    snprintf(r.host, sizeof(r.host), "%s", host);
    return r;
}

static void test_derp_record(void)
{
    tl_derp_addr_t r = derp_rec("derp16b.tailscale.com", 203, 0, 113, 16, 3478);
    r.port = 8443;
    uint8_t b[TL_ADDR_BLOB_MAX];
    const size_t n = tl_derp_addr_encode(&r, b, sizeof(b));
    tl_derp_addr_t d;
    memset(&d, 0x5a, sizeof(d));
    check("derp-rec/roundtrip",
          n == TL_DERP_ADDR_HDR + 21 && b[0] == TL_ADDR_REC_V1 && tl_derp_addr_decode(b, n, &d) &&
          memcmp(&d, &r, sizeof(r)) == 0);

    tl_derp_addr_t nohost = r, crlf = r;
    nohost.host[0] = '\0';
    snprintf(crlf.host, sizeof(crlf.host), "x\r\ny");
    check("derp-rec/encode-needs-room-and-a-host",
          tl_derp_addr_encode(&r, b, n - 1) == 0 &&
          tl_derp_addr_encode(&nohost, b, sizeof(b)) == 0 &&
          tl_derp_addr_encode(&crlf, b, sizeof(b)) == 0);

    uint8_t g[TL_ADDR_BLOB_MAX + 8];
    tl_derp_addr_encode(&r, g, sizeof(g));
    int bad = 0;
    g[0] = 2;                       bad += tl_derp_addr_decode(g, n, &d);   /* version */
    g[0] = TL_ADDR_REC_V1;
    bad += tl_derp_addr_decode(g, TL_DERP_ADDR_HDR, &d);                    /* no host */
    bad += tl_derp_addr_decode(g, 3, &d);                                   /* truncated */
    bad += tl_derp_addr_decode(g, TL_ADDR_BLOB_MAX + 1, &d);                /* too long */
    bad += tl_derp_addr_decode(NULL, n, &d);
    g[TL_DERP_ADDR_HDR + 4] = '\n'; bad += tl_derp_addr_decode(g, n, &d);   /* corrupt host */
    check("derp-rec/rejects-version-length-host", bad == 0);

    /* An address that is not worth a connect decodes as none (resolve). */
    tl_derp_addr_t lo = derp_rec("derp16b.tailscale.com", 127, 0, 0, 1, 3478);
    const size_t ln = tl_derp_addr_encode(&lo, b, sizeof(b));
    check("derp-rec/unusable-ip-is-none",
          tl_derp_addr_decode(b, ln, &d) && ip_is(d.ipv4, 0, 0, 0, 0) &&
          strcmp(d.host, "derp16b.tailscale.com") == 0);
}

static void test_ctl_record(void)
{
    static const uint8_t ip[4] = { 192, 0, 2, 10 }, lo[4] = { 127, 0, 0, 1 };
    const char *host = "controlplane.tailscale.com";
    uint8_t b[TL_ADDR_BLOB_MAX], out[4] = { 0 };
    const size_t n = tl_ctl_addr_encode(ip, host, b, sizeof(b));
    check("ctl-rec/roundtrip", n == TL_CTL_ADDR_HDR + strlen(host) &&
                               tl_ctl_addr_decode(b, n, host, out) && ip_is(out, 192, 0, 2, 10));
    memset(out, 0, 4);
    check("ctl-rec/other-control-host-ignored",
          !tl_ctl_addr_decode(b, n, "headscale.example", out) &&
          !tl_ctl_addr_decode(b, n, "controlplane.tailscale.co", out) && ip_is(out, 0, 0, 0, 0));
    uint8_t c[TL_ADDR_BLOB_MAX];
    memcpy(c, b, sizeof(c));
    c[0] = 7;
    check("ctl-rec/rejects-length-version",
          !tl_ctl_addr_decode(b, n - 1, host, out) && !tl_ctl_addr_decode(b, 0, host, out) &&
          !tl_ctl_addr_decode(c, n, host, out) && !tl_ctl_addr_decode(NULL, n, host, out));
    memcpy(c, b, sizeof(c));
    memcpy(c + 1, lo, 4);
    check("ctl-rec/no-unusable-address",
          tl_ctl_addr_encode(lo, host, b, sizeof(b)) == 0 && !tl_ctl_addr_decode(c, n, host, out));
}

/* ---- From the netmap, at boot, and what changes ----------------------- */

static void netmap_with(tl_netmap_t *nm, int region, const char *host, int a, int b, int c,
                        int d, uint16_t stun, uint16_t port)
{
    memset(nm, 0, sizeof(*nm));
    nm->have_derp_map = true;
    nm->n_derp_regions = 1;
    tl_derp_region_t *r = &nm->derp_regions[0];
    r->region_id = region;
    r->n_nodes = 2;
    snprintf(r->nodes[0].hostname, sizeof(r->nodes[0].hostname), "%s", host);
    r->nodes[0].region_id = region;
    r->nodes[0].port = port;
    r->nodes[0].stun_port = stun;
    r->nodes[0].ipv4[0] = (uint8_t)a; r->nodes[0].ipv4[1] = (uint8_t)b;
    r->nodes[0].ipv4[2] = (uint8_t)c; r->nodes[0].ipv4[3] = (uint8_t)d;
    snprintf(r->nodes[1].hostname, sizeof(r->nodes[1].hostname), "second.example");
    r->nodes[1].ipv4[0] = 198; r->nodes[1].ipv4[1] = 51; r->nodes[1].ipv4[2] = 100;
    r->nodes[1].ipv4[3] = 2;
}

static void test_from_netmap(void)
{
    static tl_netmap_t nm;
    tl_derp_addr_t a;
    netmap_with(&nm, 16, "derp16b.tailscale.com", 203, 0, 113, 16, 3478, 0);
    check("netmap/first-node-of-home-region",
          tl_derp_addr_from_netmap(&nm, 16, &a) && a.region == 16 && a.port == 0 &&
          a.stun_port == 3478 && ip_is(a.ipv4, 203, 0, 113, 16) &&
          strcmp(a.host, "derp16b.tailscale.com") == 0);
    check("netmap/other-region-none", !tl_derp_addr_from_netmap(&nm, 17, &a) &&
                                      !tl_derp_addr_from_netmap(&nm, 0, &a));
    netmap_with(&nm, 16, "derp16b.tailscale.com", 127, 0, 0, 1, 0, 8443);
    check("netmap/unusable-ip-none-stun-off-port",
          tl_derp_addr_from_netmap(&nm, 16, &a) && ip_is(a.ipv4, 0, 0, 0, 0) &&
          a.stun_port == 0 && a.port == 8443);
    netmap_with(&nm, 16, "", 203, 0, 113, 16, 3478, 0);
    check("netmap/nameless-node-skipped", !tl_derp_addr_from_netmap(&nm, 16, &a));
    nm.n_derp_regions = 0;   /* DERPMap without the home region */
    check("netmap/region-absent", !tl_derp_addr_from_netmap(&nm, 16, &a));

    /* What a netmap's record changes. */
    tl_derp_addr_t cur = derp_rec("derp16b.tailscale.com", 203, 0, 113, 16, 3478), nx = cur;
    check("diff/same", tl_derp_addr_diff(&cur, &nx) == 0);
    nx.ipv4[3] = 17;
    check("diff/address-only", tl_derp_addr_diff(&cur, &nx) == TL_DERP_ADDR);
    nx = cur;
    nx.stun_port = 0;
    check("diff/stun-only", tl_derp_addr_diff(&cur, &nx) == TL_DERP_ADDR);
    nx = cur;
    snprintf(nx.host, sizeof(nx.host), "derp16c.tailscale.com");
    nx.ipv4[3] = 18;
    check("diff/moved-host", tl_derp_addr_diff(&cur, &nx) == (TL_DERP_MOVED | TL_DERP_ADDR));
    nx = cur;
    nx.port = 8443;
    check("diff/moved-port", tl_derp_addr_diff(&cur, &nx) == TL_DERP_MOVED);
    /* The boot record (Kconfig host, no address) → the netmap's node of
     * the same host: an address learnt, no reroute. */
    tl_derp_addr_t boot;
    tl_derp_addr_boot(NULL, 0, 16, "derp16b.tailscale.com", &boot);
    check("diff/boot-default-learns-address", tl_derp_addr_diff(&boot, &cur) == TL_DERP_ADDR);
}

static void test_boot_record(void)
{
    uint8_t b[TL_ADDR_BLOB_MAX];
    tl_derp_addr_t r = derp_rec("derp16c.tailscale.com", 203, 0, 113, 16, 3478), a;
    size_t n = tl_derp_addr_encode(&r, b, sizeof(b));
    tl_derp_addr_boot(b, n, 16, "derp16b.tailscale.com", &a);
    check("boot/stored-record", memcmp(&a, &r, sizeof(r)) == 0);
    tl_derp_addr_boot(b, n, 17, "derp17b.tailscale.com", &a);
    check("boot/new-home-region-ignores-it",
          a.region == 17 && strcmp(a.host, "derp17b.tailscale.com") == 0 &&
          ip_is(a.ipv4, 0, 0, 0, 0) && a.stun_port == 0);
    b[TL_DERP_ADDR_HDR] = ' ';
    tl_derp_addr_boot(b, n, 16, "derp16b.tailscale.com", &a);
    check("boot/corrupt-is-kconfig", strcmp(a.host, "derp16b.tailscale.com") == 0 &&
                                     ip_is(a.ipv4, 0, 0, 0, 0));
    tl_derp_addr_boot(NULL, 0, 16, "derp16b.tailscale.com", &a);
    check("boot/none-is-kconfig", a.region == 16 && strcmp(a.host, "derp16b.tailscale.com") == 0 &&
                                  ip_is(a.ipv4, 0, 0, 0, 0));

    uint8_t ip[4];
    uint16_t port = 0;
    check("stun/home-node-without-dns",
          tl_derp_addr_stun(&r, ip, &port) && ip_is(ip, 203, 0, 113, 16) && port == 3478);
    tl_derp_addr_t off = r;
    off.stun_port = 0;
    check("stun/off-or-no-address-means-dns",
          !tl_derp_addr_stun(&off, ip, &port) && !tl_derp_addr_stun(&a, ip, &port) &&
          !tl_derp_addr_stun(NULL, ip, &port));
}

/* ---- Written only on change, over reboots ----------------------------- */

typedef struct {
    uint8_t b[TL_ADDR_BLOB_MAX];
    size_t  len;
    int     writes;
    int     fail;          /* the next write fails */
} fake_nvs_t;

static int fake_write(const uint8_t *b, size_t n, const void *ctx)
{
    fake_nvs_t *f = (fake_nvs_t *)ctx;
    f->writes++;
    if (f->fail) {
        f->fail = 0;
        return -1;
    }
    memcpy(f->b, b, n);
    f->len = n;
    return 0;
}

/* A boot: the mirror loaded from what NVS holds. */
static void boot_load(tl_addr_blob_t *m, const fake_nvs_t *f)
{
    memset(m, 0, sizeof(*m));
    memcpy(m->b, f->b, f->len);
    m->len = (uint8_t)f->len;
}

/* What the housekeeping poll stores for a netmap's home node. */
static int store_netmap(tl_addr_blob_t *m, fake_nvs_t *f, const tl_netmap_t *nm)
{
    tl_derp_addr_t a;
    uint8_t b[TL_ADDR_BLOB_MAX];
    if (!tl_derp_addr_from_netmap(nm, 16, &a)) return -2;
    const size_t n = tl_derp_addr_encode(&a, b, sizeof(b));
    return tl_addr_store(m, b, n, fake_write, f);
}

static void test_store_on_change(void)
{
    static tl_netmap_t nm;
    fake_nvs_t nvs;
    memset(&nvs, 0, sizeof(nvs));
    tl_addr_blob_t m;

    /* First boot: nothing stored; the first netmap writes once, the
     * hourly-ish polls and later identical frames never again. */
    boot_load(&m, &nvs);
    netmap_with(&nm, 16, "derp16b.tailscale.com", 203, 0, 113, 16, 3478, 0);
    int r1 = store_netmap(&m, &nvs, &nm);
    int r2 = store_netmap(&m, &nvs, &nm);
    int r3 = store_netmap(&m, &nvs, &nm);
    check("store/first-netmap-one-write", r1 == 1 && r2 == 0 && r3 == 0 && nvs.writes == 1);

    /* Reboot: the same map again costs nothing. */
    boot_load(&m, &nvs);
    tl_derp_addr_t a;
    tl_derp_addr_boot(m.b, m.len, 16, "derp16b.tailscale.com", &a);
    check("store/reboot-boots-from-record", ip_is(a.ipv4, 203, 0, 113, 16) && a.stun_port == 3478);
    for (int i = 0; i < 100; i++) (void)store_netmap(&m, &nvs, &nm);
    check("store/reboot-same-map-no-write", nvs.writes == 1);

    /* The map moves the node's address: one write, then quiet again. */
    netmap_with(&nm, 16, "derp16b.tailscale.com", 203, 0, 113, 99, 3478, 0);
    r1 = store_netmap(&m, &nvs, &nm);
    r2 = store_netmap(&m, &nvs, &nm);
    check("store/address-change-one-write", r1 == 1 && r2 == 0 && nvs.writes == 2 &&
                                            nvs.b[10] == 99);

    /* A failed write: the mirror still follows (no retry per frame); the
     * next boot reloads the old record and writes once. */
    netmap_with(&nm, 16, "derp16c.tailscale.com", 203, 0, 113, 50, 3478, 0);
    nvs.fail = 1;
    r1 = store_netmap(&m, &nvs, &nm);
    r2 = store_netmap(&m, &nvs, &nm);
    check("store/failed-write-not-retried-per-call", r1 == -1 && r2 == 0 && nvs.writes == 3);
    boot_load(&m, &nvs);
    r1 = store_netmap(&m, &nvs, &nm);
    check("store/failed-write-retried-next-boot", r1 == 1 && nvs.writes == 4 &&
                                                  nvs.b[TL_DERP_ADDR_HDR + 6] == 'c');

    /* Nothing to store (the map has no home node) and an empty record
     * never write. */
    nm.n_derp_regions = 0;
    r1 = store_netmap(&m, &nvs, &nm);
    check("store/no-node-no-write", r1 == -2 && nvs.writes == 4 &&
                                    tl_addr_store(&m, NULL, 0, fake_write, &nvs) == -1 &&
                                    nvs.writes == 4);

    /* The control record: a connect to the same address writes nothing;
     * a fallback that came up elsewhere writes the new one once. */
    fake_nvs_t cn;
    memset(&cn, 0, sizeof(cn));
    tl_addr_blob_t cm;
    boot_load(&cm, &cn);
    const char *host = "controlplane.tailscale.com";
    static const uint8_t ip1[4] = { 192, 0, 2, 10 }, ip2[4] = { 192, 0, 2, 20 };
    uint8_t b[TL_ADDR_BLOB_MAX];
    int w = 0;
    for (int i = 0; i < 20; i++) {
        size_t n = tl_ctl_addr_encode(ip1, host, b, sizeof(b));
        w += tl_addr_store(&cm, b, n, fake_write, &cn);
    }
    boot_load(&cm, &cn);
    for (int i = 0; i < 20; i++) {
        size_t n = tl_ctl_addr_encode(ip1, host, b, sizeof(b));
        w += tl_addr_store(&cm, b, n, fake_write, &cn);
    }
    check("store/ctl-same-address-one-write-ever", w == 1 && cn.writes == 1);
    size_t n = tl_ctl_addr_encode(ip2, host, b, sizeof(b));
    w = tl_addr_store(&cm, b, n, fake_write, &cn);
    uint8_t got[4];
    check("store/ctl-new-address-one-write",
          w == 1 && cn.writes == 2 && tl_ctl_addr_decode(cn.b, cn.len, host, got) &&
          ip_is(got, 192, 0, 2, 20));
}

int main(void)
{
    test_ipv4();
    test_stun_port();
    test_host();
    test_derp_record();
    test_ctl_record();
    test_from_netmap();
    test_boot_record();
    test_store_on_change();
    if (s_fails == 0) printf("\nALL OK\n");
    return s_fails ? 1 : 0;
}
