/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — CRC-32 (ISO 3309 / Ethernet / ZIP) fixture.
 *
 * CRC-32 is a cyclic redundancy check widely used in Ethernet, ZIP files,
 * and ESP32 NVS/OTA.  It uses the reflected polynomial 0xEDB88320 (reversed
 * bit order of CRC-32/ISO-HDLC polynomial 0x04C11DB7).
 *
 * Distinctive decompiler idioms:
 *   1. `for (j=0; j<8; j++) crc = (crc&1) ? (crc>>1)^POLY : (crc>>1)` — bit-by-bit table gen
 *   2. `crc = (crc>>8) ^ crc32_table[(crc^byte)&0xFF]` — table-driven per-byte update
 *   3. `crc ^= 0xFFFFFFFF` at start AND end (init with all-1s, final XOR with all-1s)
 *   4. Lookup table of 256 entries indexed by byte value XOR'd with CRC low byte
 *   5. `POLY = 0xEDB88320u` — reflected polynomial constant
 *
 * Input: "Hello" (5 bytes: 0x48,0x65,0x6C,0x6C,0x6F)
 * CRC-32("Hello") = 0xF7D18982
 *
 * Encoding:
 *   n_bytes  = 5                      = 0x05
 *   crc_b1   = (crc >> 16) & 0xFF     = 0xD1 = 209
 *   crc_b0   = (crc >> 8)  & 0xFF     = 0x89 = 137
 *
 * g_result = (n_bytes << 16) | (crc_b1 << 8) | crc_b0 = 0x05D189 ✓ (5,209,137 distinct)
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CRC32_POLY 0xEDB88320u

static uint32_t crc32_table[256];

static void crc32_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++)
            crc = (crc & 1u) ? (crc >> 1) ^ CRC32_POLY : (crc >> 1);
        crc32_table[i] = crc;
    }
}

static uint32_t crc32_compute(const unsigned char *buf, int n)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (int i = 0; i < n; i++)
        crc = (crc >> 8) ^ crc32_table[(crc ^ buf[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFu;
}

void test_crc32(void)
{
    crc32_init();
    static const unsigned char msg[5] = { 'H', 'e', 'l', 'l', 'o' };
    uint32_t crc = crc32_compute(msg, 5);
    /* crc = 0xF7D18982; n_bytes=5, crc_b1=0xD1, crc_b0=0x89 */
    g_result = ((uint32_t)5 << 16)
             | (((crc >> 16) & 0xFF) << 8)
             | ((crc >>  8) & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_crc32();
    for (;;);
}
