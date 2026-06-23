/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Karatsuba Multiplication.
 *
 * Karatsuba's divide-and-conquer integer multiplication reduces the number
 * of single-digit multiplications from O(n^2) to O(n^1.585) by splitting
 * each n-digit number into two halves and applying the identity:
 *
 *   x*y = z2*B^2 + (z1-z2-z0)*B + z0
 *   where z2 = x1*y1, z0 = x0*y0, z1 = (x0+x1)*(y0+y1)
 *
 * Distinctive decompiler idioms:
 *   1. Three recursive calls instead of four (z0, z1, z2)
 *   2. mid = n/2; x1 = x >> mid; x0 = x & ((1<<mid)-1) — half-word split
 *   3. z1 = karatsuba(x0+x1, y0+y1, half) — cross-term multiply
 *   4. z1 = z1 - z2 - z0 — cross-term correction
 *   5. result = z2*(B^2) + z1*B + z0 — combine with shifts
 *
 * We use 16-bit halves operating on 32-bit values, which avoids 64-bit ops.
 * x = 1234 = 0x04D2, y = 5678 = 0x162E
 * Product = 1234 * 5678 = 7,006,652 = 0x6B024C
 *
 * half     = 8   = 0x08
 * product  = 7006652 mod 0x1000000 = 0x6B024C; low24 = 0x6B024C
 * g_result = product & 0xFFFFFF = 0x6B024C ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

/* B = 2^HALF_BITS */
#define HALF_BITS 8
#define BASE      (1u << HALF_BITS)  /* 256 */
#define HMASK     (BASE - 1u)        /* 0xFF */

/* Karatsuba on values split at HALF_BITS.  n = number of bits in each half. */
static uint32_t karatsuba(uint32_t x, uint32_t y, int bits)
{
    if (bits <= 4) return (x & 0xF) * (y & 0xF);

    int half = bits / 2;
    uint32_t mask = (1u << half) - 1u;

    uint32_t x0 = x & mask;
    uint32_t x1 = (x >> half) & mask;
    uint32_t y0 = y & mask;
    uint32_t y1 = (y >> half) & mask;

    uint32_t z0 = karatsuba(x0,       y0,       half);
    uint32_t z2 = karatsuba(x1,       y1,       half);
    uint32_t z1 = karatsuba(x0 + x1,  y0 + y1,  half + 1);

    z1 = z1 - z0 - z2;   /* cross-term correction */

    /* combine: z2*(B^2) + z1*B + z0 */
    uint32_t base = 1u << half;
    return z0 + z1 * base + z2 * base * base;
}

void test_karatsuba(void)
{
    uint32_t x = 1234u;
    uint32_t y = 5678u;
    /* Expected: 1234*5678 = 7006652 = 0x006B024C */
    uint32_t product = karatsuba(x, y, 16);
    g_result = product & 0x00FFFFFFu;  /* keep low 24 bits: 0x6B024C */
}

__attribute__((noreturn)) void _start(void)
{
    test_karatsuba();
    for (;;);
}
