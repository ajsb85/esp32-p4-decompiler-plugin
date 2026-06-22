/* ESP32-P4 Number Theory Round-Trip Test Runner
 *
 * Demonstrates how a bare-metal fixture (test/roundtrip/test_twin_primes.c)
 * is ported to a FreeRTOS IDF task for HIL testing via pytest-embedded.
 *
 * The _start() entry point from the bare-metal fixture is replaced with a
 * FreeRTOS task.  The algorithm body is unchanged.  Unity assertions are
 * added, and RESULT:0x%08X is printed to UART for pytest-embedded capture.
 */
#include <stdio.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "unity.h"
#include "esp_log.h"

static const char *TAG = "esp32p4_numtheory";

/* Declared in test_twin_primes_idf.c */
void test_twin_primes_idf(void);

static void test_task(void *arg)
{
    ESP_LOGI(TAG, "ESP32-P4 Number Theory Round-Trip Tests starting");

    UNITY_BEGIN();
    RUN_TEST(test_twin_primes_idf);
    int failed = UNITY_END();

    printf("ALL_TESTS_DONE failed=%d\n", failed);
    vTaskDelete(NULL);
}

void app_main(void)
{
    printf("ESP32-P4 Ghidra Plugin Number Theory Test Build\n");
    printf("IDF version: %s\n", IDF_VER);
    /* Give console time to attach */
    vTaskDelay(pdMS_TO_TICKS(500));
    xTaskCreate(test_task, "test_task", 8192, NULL, 5, NULL);
}
