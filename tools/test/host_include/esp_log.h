/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for ESP-IDF's esp_log.h. The macros keep printf
 * format checking (and use the tag, so `static const char *TAG` is not
 * "unused"), but print only with TL_HOST_LOG set in the environment, to
 * stderr — expected-failure paths in the KATs log, and the CI counts
 * lines. */
#pragma once

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static inline __attribute__((format(printf, 3, 4)))
void tl_host_log(char lvl, const char *tag, const char *fmt, ...)
{
    if (getenv("TL_HOST_LOG") == NULL) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%c (%s) ", lvl, tag);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

#define ESP_LOGE(tag, fmt, ...) tl_host_log('E', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) tl_host_log('W', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) tl_host_log('I', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) tl_host_log('D', tag, fmt, ##__VA_ARGS__)
#define ESP_LOGV(tag, fmt, ...) tl_host_log('V', tag, fmt, ##__VA_ARGS__)
