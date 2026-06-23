/* ESP32-P4 Algorithm Round-Trip Test Runner
 * Runs algorithm tests via FreeRTOS task, prints RESULT lines to UART.
 * Compatible with pytest-embedded IdfDut fixture. */
#include <stdio.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "unity.h"
#include "algorithms.h"
#include "esp_log.h"

static const char *TAG = "esp32p4_algo_test";

static void test_task(void *arg) {
    ESP_LOGI(TAG, "ESP32-P4 Algorithm Round-Trip Tests starting");

    /* Run each test suite */
    UNITY_BEGIN();
    RUN_TEST(test_crc32_idf);
    RUN_TEST(test_fibonacci_idf);
    RUN_TEST(test_primes_idf);
    int failed = UNITY_END();

    /* Print summary for pytest-embedded to detect */
    printf("ALL_TESTS_DONE failed=%d\n", failed);
    vTaskDelete(NULL);
}

void app_main(void) {
    printf("ESP32-P4 Ghidra Plugin Round-Trip Test Build\n");
    printf("IDF version: %s\n", IDF_VER);
    /* Give console time to attach */
    vTaskDelay(pdMS_TO_TICKS(500));
    xTaskCreate(test_task, "test_task", 8192, NULL, 5, NULL);
}
