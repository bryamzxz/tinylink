// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "tmp117.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/i2c_master.h"
#include "esp_log.h"

static const char *TAG = "tmp117";

#define TMP117_REG_TEMP        0x00
#define TMP117_REG_CONFIG      0x01
#define TMP117_REG_DEVICE_ID   0x07
#define TMP117_DEVICE_ID       0x0117
#define TMP117_RAW_INVALID     ((int16_t)0x8000)
#define TMP117_LSB_NUMER       78125          /* 7.8125 m°C × 10⁴ */
#define TMP117_LSB_DENOM       10000

static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev;
static bool                    s_inited;

static esp_err_t read_reg16(uint8_t reg, uint16_t *out)
{
    uint8_t buf[2] = {0};
    /* -1 = no timeout: the bus driver applies its default. */
    esp_err_t err = i2c_master_transmit_receive(s_dev, &reg, 1, buf, 2, -1);
    if (err != ESP_OK) return err;
    *out = (uint16_t)((buf[0] << 8) | buf[1]);
    return ESP_OK;
}

esp_err_t tmp117_init(int sda_gpio, int scl_gpio, uint8_t i2c_addr)
{
    if (s_inited) return ESP_OK;

    i2c_master_bus_config_t bus_config = {
        .i2c_port          = I2C_NUM_0,
        .sda_io_num        = sda_gpio,
        .scl_io_num        = scl_gpio,
        .clk_source        = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    esp_err_t err = i2c_new_master_bus(&bus_config, &s_bus);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c_new_master_bus: %s", esp_err_to_name(err));
        return err;
    }

    i2c_device_config_t dev_config = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = i2c_addr,
        .scl_speed_hz    = 100000,
    };
    err = i2c_master_bus_add_device(s_bus, &dev_config, &s_dev);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c_master_bus_add_device: %s", esp_err_to_name(err));
        i2c_del_master_bus(s_bus);
        s_bus = NULL;
        return err;
    }

    /* Cheap sanity probe: read DEVICE_ID and confirm the chip is alive.
     * If the I²C lines are floating or the address is wrong, this is
     * where we find out — much cheaper than diagnosing a frozen
     * conversion later. */
    uint16_t did = 0;
    err = read_reg16(TMP117_REG_DEVICE_ID, &did);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "DEVICE_ID read failed: %s", esp_err_to_name(err));
        return err;
    }
    if ((did & 0x0FFF) != TMP117_DEVICE_ID) {
        ESP_LOGE(TAG, "unexpected DEVICE_ID 0x%04x (want 0x%04x)",
                 did, TMP117_DEVICE_ID);
        return ESP_ERR_NOT_FOUND;
    }
    ESP_LOGI(TAG, "TMP117 detected (DEVICE_ID=0x%04x)", did);
    s_inited = true;
    return ESP_OK;
}

esp_err_t tmp117_read_milli_c(int32_t *out_milli_c)
{
    if (!s_inited || out_milli_c == NULL) return ESP_ERR_INVALID_STATE;

    uint16_t raw = 0;
    esp_err_t err = read_reg16(TMP117_REG_TEMP, &raw);
    if (err != ESP_OK) return err;

    /* 0x8000 signals a conversion-in-progress. Default conversion time
     * with AVG=8 / CONV=4 is ~1 s; one retry covers a power-on race. */
    if ((int16_t)raw == TMP117_RAW_INVALID) {
        vTaskDelay(pdMS_TO_TICKS(150));
        err = read_reg16(TMP117_REG_TEMP, &raw);
        if (err != ESP_OK) return err;
        if ((int16_t)raw == TMP117_RAW_INVALID) return ESP_ERR_TIMEOUT;
    }

    int32_t signed_raw = (int32_t)(int16_t)raw;
    /* Order of ops: multiply first (fits in int32 for ±32767 × 78125
     * ≈ 2.56e9, which exceeds int32 max 2.15e9 — lift to int64). */
    int64_t milli = ((int64_t)signed_raw * TMP117_LSB_NUMER) /
                    TMP117_LSB_DENOM;
    *out_milli_c = (int32_t)milli;
    return ESP_OK;
}

#endif /* ESP_PLATFORM */
