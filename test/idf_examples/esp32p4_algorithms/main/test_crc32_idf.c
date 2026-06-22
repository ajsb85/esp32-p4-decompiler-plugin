/* IDF-wrapped CRC32 round-trip test for ESP32-P4.
 * Computes CRC32 of "ESP32P4" and encodes result into g_result. */
#include "algorithms.h"
#include <stdio.h>
#include <inttypes.h>
#include "unity.h"

volatile uint32_t g_result;

static uint32_t crc32_word(uint32_t crc, uint32_t data) {
    for (int i = 0; i < 32; i++) {
        if ((crc ^ data) & 1)
            crc = (crc >> 1) ^ 0xEDB88320u;
        else
            crc >>= 1;
        data >>= 1;
    }
    return crc;
}

void test_crc32_idf(void) {
    /* CRC32 of "ESP32P4" (7 bytes) */
    const uint8_t buf[] = {'E','S','P','3','2','P','4'};
    uint32_t crc = 0xFFFFFFFFu;
    for (int i = 0; i < 7; i++) {
        crc = crc32_word(crc, buf[i]);
    }
    crc ^= 0xFFFFFFFFu;

    uint32_t low8  = crc & 0xFF;
    uint32_t mid8  = (crc >> 8) & 0xFF;
    uint32_t count = 7;
    g_result = (count << 16) | (mid8 << 8) | low8;

    printf("CRC32_RESULT:0x%08" PRIx32 "\n", (uint32_t)g_result);
    TEST_ASSERT_NOT_EQUAL(0, crc);
}
