/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for FreeRTOS's semphr.h: a mutex is a pthread mutex
 * (derp_client.c creates its write lock with it; the host test takes and
 * gives it through its own derp_wlock.h primitives). */
#pragma once

#include <pthread.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"

typedef void *SemaphoreHandle_t;

static inline SemaphoreHandle_t xSemaphoreCreateMutex(void)
{
    pthread_mutex_t *m = (pthread_mutex_t *)malloc(sizeof(*m));
    if (m != NULL && pthread_mutex_init(m, NULL) != 0) {
        free(m);
        m = NULL;
    }
    return m;
}
