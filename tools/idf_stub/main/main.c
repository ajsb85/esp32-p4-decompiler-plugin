/*
 * ESP32-P4 FIDB stub — touches every important IDF component so their
 * archives get compiled and fingerprinted into tools/esp32p4-idf6.fidb.
 *
 * This file is never flashed; it exists solely to drive the build.
 */
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "nvs_flash.h"
#include "esp_heap_caps.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "driver/i2c_master.h"
#include "driver/spi_master.h"

static const char *TAG = "fidb_stub";

static void heap_demo(void)
{
    void *p = heap_caps_malloc(64, MALLOC_CAP_DEFAULT);
    if (p) {
        heap_caps_free(p);
    }
    size_t free_sz = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    ESP_LOGI(TAG, "free heap: %zu", free_sz);
}

static void gpio_demo(void)
{
    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << GPIO_NUM_4),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
    gpio_set_level(GPIO_NUM_4, 1);
    gpio_set_level(GPIO_NUM_4, 0);
}

static void timer_demo(void)
{
    int64_t t = esp_timer_get_time();
    ESP_LOGI(TAG, "uptime: %lld us", t);
}

static void rtos_demo(void)
{
    QueueHandle_t q = xQueueCreate(4, sizeof(uint32_t));
    SemaphoreHandle_t sem = xSemaphoreCreateMutex();
    uint32_t val = 42;
    xQueueSend(q, &val, 0);
    xQueueReceive(q, &val, 0);
    xSemaphoreTake(sem, portMAX_DELAY);
    xSemaphoreGive(sem);
    vQueueDelete(q);
    vSemaphoreDelete(sem);
}

static void nvs_demo(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    nvs_handle_t h;
    nvs_open("storage", NVS_READWRITE, &h);
    nvs_set_i32(h, "boot_count", 0);
    nvs_commit(h);
    nvs_close(h);
}

void app_main(void)
{
    ESP_LOGI(TAG, "FIDB stub — IDF %s", esp_get_idf_version());
    heap_demo();
    gpio_demo();
    timer_demo();
    rtos_demo();
    nvs_demo();
}
