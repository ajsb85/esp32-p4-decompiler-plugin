/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 round-trip fixture: hash functions
 *
 * Exercises DJB2, FNV-1a, and polynomial rolling hash.
 * Compiled with -O2: patterns recognizable by decompiler.
 *
 * g_result = djb2(msg,8) ^ fnv1a_32(msg,8) ^ poly_hash(msg,8,31)
 *          = 0x68C2C044 ^ 0x9D2808FC ^ 0xD49A45ED = 0x21708D55
 */
#include <stdint.h>

volatile uint32_t g_result = 0;

static uint32_t djb2(const uint8_t *s, uint32_t len)
{
    uint32_t hash = 5381u;
    for (uint32_t i = 0; i < len; i++)
        hash = ((hash << 5) + hash) ^ s[i];
    return hash;
}

static uint32_t fnv1a_32(const uint8_t *s, uint32_t len)
{
    uint32_t hash = 2166136261u;
    for (uint32_t i = 0; i < len; i++) {
        hash ^= s[i];
        hash *= 16777619u;
    }
    return hash;
}

static uint32_t poly_hash(const uint8_t *s, uint32_t len, uint32_t base)
{
    uint32_t hash = 0;
    for (uint32_t i = 0; i < len; i++)
        hash = hash * base + s[i];
    return hash;
}

void _start(void)
{
    static const uint8_t msg[8] = {0x48,0x65,0x6C,0x6C,0x6F,0x21,0x42,0x00};
    g_result = djb2(msg, 8) ^ fnv1a_32(msg, 8) ^ poly_hash(msg, 8, 31u);
    while (1) {}
}
