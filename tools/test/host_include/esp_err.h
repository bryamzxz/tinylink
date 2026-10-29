/* SPDX-License-Identifier: MIT
 * Host-only stub header — just enough of ESP-IDF's esp_err.h for
 * components/tinylink/include/tinylink.h to compile in host tests
 * (test_stats). Values match the ESP-IDF originals. */

#ifndef HOST_STUB_ESP_ERR_H_
#define HOST_STUB_ESP_ERR_H_

typedef int esp_err_t;
#define ESP_OK    0
#define ESP_FAIL  -1

#endif
