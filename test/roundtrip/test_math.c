/* SPDX-License-Identifier: Apache-2.0
 * Extended round-trip test: integer math algorithms.
 *
 * Exercises: bit manipulation, Newton–Raphson convergence loop,
 *            popcount magic constants, bit-reversal swaps.
 *
 * Expected pattern detection:
 *   popcount      — 0x55555555 / 0x33333333 / 0x0F0F0F0F magic
 *   bit_reverse   — 0xAAAAAAAA / 0x55555555 / swap pattern
 *   isqrt         — while convergence + divide
 *   ilog2         — right-shift until zero
 *
 * Expected g_result (computed statically):
 *   popcount(0xDEADBEEF) = 24
 *   isqrt(10000)         = 100
 *   bit_reverse(1u<<24)  = 0x00000080
 *   ilog2(1024)          = 10
 *   g_result = 24 ^ 100 ^ 0x80 ^ 10
 *            = 0x18 ^ 0x64 ^ 0x80 ^ 0x0A
 *            = 0x7C ^ 0x80 ^ 0x0A
 *            = 0xFC ^ 0x0A = 0xF6 = 246
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Hamming weight (population count) using parallel-prefix algorithm */
static uint32_t popcount(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    x = (x + (x >> 4)) & 0x0F0F0F0Fu;
    return (x * 0x01010101u) >> 24;
}

/* Bit reversal using parallel-swap network */
static uint32_t bit_reverse(uint32_t x) {
    x = ((x & 0xAAAAAAAAu) >> 1)  | ((x & 0x55555555u) << 1);
    x = ((x & 0xCCCCCCCCu) >> 2)  | ((x & 0x33333333u) << 2);
    x = ((x & 0xF0F0F0F0u) >> 4)  | ((x & 0x0F0F0F0Fu) << 4);
    x = ((x & 0xFF00FF00u) >> 8)  | ((x & 0x00FF00FFu) << 8);
    return (x >> 16) | (x << 16);
}

/* Integer square root — Newton–Raphson convergence */
static uint32_t isqrt(uint32_t n) {
    if (n == 0) return 0;
    uint32_t x = n;
    uint32_t y = (x + 1) >> 1;
    while (y < x) {
        x = y;
        y = (x + n / x) >> 1;
    }
    return x;
}

/* Integer log2 (floor) — shift until zero */
static uint32_t ilog2(uint32_t n) {
    if (n == 0) return 0;
    uint32_t r = 0;
    while (n > 1) {
        n >>= 1;
        r++;
    }
    return r;
}

/* Count leading zeros */
static uint32_t clz32(uint32_t x) {
    if (x == 0) return 32;
    uint32_t n = 0;
    if (x <= 0x0000FFFFu) { n += 16; x <<= 16; }
    if (x <= 0x00FFFFFFu) { n +=  8; x <<=  8; }
    if (x <= 0x0FFFFFFFu) { n +=  4; x <<=  4; }
    if (x <= 0x3FFFFFFFu) { n +=  2; x <<=  2; }
    if (x <= 0x7FFFFFFFu) { n +=  1;            }
    return n;
}

void _start(void) {
    uint32_t pc = popcount(0xDEADBEEFu);  /* = 24 = 0x18 */
    uint32_t sq = isqrt(10000u);           /* = 100 = 0x64 */
    uint32_t br = bit_reverse(1u << 24);   /* = 0x00000080 */
    uint32_t lg = ilog2(1024u);            /* = 10 = 0x0A  */
    uint32_t cz = clz32(0x00010000u);      /* = 15 = 0x0F  */

    g_result = pc ^ sq ^ br ^ lg ^ cz;
    /* = 0x18 ^ 0x64 ^ 0x80 ^ 0x0A ^ 0x0F
     * = 0x7C ^ 0x80 ^ 0x0A ^ 0x0F
     * = 0xFC ^ 0x0A ^ 0x0F
     * = 0xF6 ^ 0x0F = 0xF9 = 249 */

    for (;;);
}
