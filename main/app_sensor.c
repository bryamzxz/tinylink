// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// TMP117 driver: continuous conversion, 8-sample average. Datasheet:
//   reg 0x00 = temperature (s16, LSB = 7.8125 m°C => divide by 128.0)
//   reg 0x01 = configuration (CONV[2:0]=000, AVG[1:0]=01 -> 8 averages,
//              MOD[1:0]=00 -> continuous conversion)

#include "app_sensor.h"

#include "driver/i2c_master.h"
#include "esp_log.h"

static const char *TAG = "app_sensor";

#define TMP117_REG_TEMP   0x00
#define TMP117_REG_CONFIG 0x01

/* AVG=01 (8 averages), MOD=00 (continuous), CONV=000.
 * High byte 0x02, low byte 0x20. */
#define TMP117_CONFIG_HI  0x02
#define TMP117_CONFIG_LO  0x20

#define TMP117_TEMP_LSB_C (1.0f / 128.0f)
#define TMP117_TEMP_MIN_C (-50.0f)
#define TMP117_TEMP_MAX_C (150.0f)

#define I2C_FREQ_HZ      100000
#define I2C_TIMEOUT_MS   100

static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev;

esp_err_t app_sensor_init(void)
{
    i2c_master_bus_config_t bus_cfg = {
        .i2c_port = CONFIG_TINYLINK_TMP117_I2C_PORT,
        .sda_io_num = CONFIG_TINYLINK_TMP117_SDA_GPIO,
        .scl_io_num = CONFIG_TINYLINK_TMP117_SCL_GPIO,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    esp_err_t err = i2c_new_master_bus(&bus_cfg, &s_bus);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c_new_master_bus: 0x%x", err);
        return err;
    }

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = CONFIG_TINYLINK_TMP117_I2C_ADDR,
        .scl_speed_hz = I2C_FREQ_HZ,
    };
    err = i2c_master_bus_add_device(s_bus, &dev_cfg, &s_dev);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c_master_bus_add_device: 0x%x", err);
        return err;
    }

    uint8_t cfg[3] = { TMP117_REG_CONFIG, TMP117_CONFIG_HI, TMP117_CONFIG_LO };
    err = i2c_master_transmit(s_dev, cfg, sizeof(cfg), I2C_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tmp117 config write: 0x%x", err);
        return err;
    }
    ESP_LOGI(TAG, "tmp117 ready on port=%d sda=%d scl=%d addr=0x%02x",
             CONFIG_TINYLINK_TMP117_I2C_PORT,
             CONFIG_TINYLINK_TMP117_SDA_GPIO,
             CONFIG_TINYLINK_TMP117_SCL_GPIO,
             CONFIG_TINYLINK_TMP117_I2C_ADDR);
    return ESP_OK;
}

esp_err_t app_sensor_read_temperature_c(float *out_temp_c)
{
    if (out_temp_c == NULL) return ESP_ERR_INVALID_ARG;
    if (s_dev == NULL)      return ESP_ERR_INVALID_STATE;

    uint8_t reg = TMP117_REG_TEMP;
    uint8_t raw[2] = {0};
    esp_err_t err = i2c_master_transmit_receive(s_dev, &reg, 1,
                                                raw, sizeof(raw), I2C_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tmp117 read: 0x%x", err);
        return err;
    }

    int16_t raw_signed = (int16_t)((raw[0] << 8) | raw[1]);
    float temp_c = raw_signed * TMP117_TEMP_LSB_C;

    if (temp_c < TMP117_TEMP_MIN_C || temp_c > TMP117_TEMP_MAX_C) {
        ESP_LOGW(TAG, "tmp117 out-of-range temp %.3f C (raw 0x%04x)",
                 temp_c, (unsigned)raw_signed);
        return ESP_ERR_INVALID_RESPONSE;
    }
    *out_temp_c = temp_c;
    return ESP_OK;
}
