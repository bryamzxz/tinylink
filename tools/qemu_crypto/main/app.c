// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Runs every suite in turn and prints one QEMU-SUITE line per suite and a
// final QEMU-DONE line, which run.sh waits for and checks.

#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

int m_chacha20(void);
int m_aead(void);
int m_poly(void);
int m_blake2s(void);
int m_hkdf(void);
int m_nacl(void);
int m_xq(void);

void app_main(void)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        { "chacha20",         m_chacha20 },
        { "chacha20poly1305", m_aead },
        { "poly1305",         m_poly },
        { "blake2s",          m_blake2s },
        { "hkdf_noise",       m_hkdf },
        { "nacl_box",         m_nacl },
        { "x25519",           m_xq },
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
        printf("=== QEMU-SUITE %s start\n", suites[i].name);
        fflush(stdout);
        const int rc = suites[i].run();
        printf("=== QEMU-SUITE %s rc=%d\n", suites[i].name, rc);
        fflush(stdout);
        failed += rc != 0;
    }
    printf("=== QEMU-DONE failed_suites=%d\n", failed);
    fflush(stdout);
    for (;;) vTaskDelay(portMAX_DELAY);   /* run.sh stops QEMU */
}
