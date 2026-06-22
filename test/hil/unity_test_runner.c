/* Unity test runner for ESP32-P4 hardware-in-the-loop round-trip tests.
 * Prints "RESULT:0x%08X" for each fixture so pytest-embedded can capture it. */

#include <stdio.h>
#include <stdint.h>
#include "unity.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Forward declarations for decompiled round-trip functions under test */
extern void test_hwlp(void);
extern volatile uint32_t g_result;

TEST_CASE("HWLP semantic fidelity", "[esp32p4][hwlp]") {
    g_result = 0;
    test_hwlp();
    printf("HWLP: executing hardware loop test\n");
    printf("RESULT:0x%08" PRIx32 "\n", (uint32_t)g_result);
    TEST_ASSERT_NOT_EQUAL(0, g_result);
}

void app_main(void) {
    printf("ESP32-P4 HIL Test Runner starting\n");
    printf("app_main\n");
    unity_run_menu();
}
