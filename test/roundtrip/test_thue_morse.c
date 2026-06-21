/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Thue-Morse sequence fixture.
 *
 * The Thue-Morse sequence T(n) is defined by the parity of popcount(n):
 *   T(n) = popcount(n) mod 2
 *   T(0)=0, T(1)=1, T(2)=1, T(3)=0, T(4)=1, T(5)=0, ...
 *
 * Equivalently: T(0)=0, T(2n)=T(n), T(2n+1)=1-T(n).
 *
 * Distinctive decompiler idioms:
 *   1. Popcount parity: shift-and-XOR accumulation for bit counting
 *   2. Recurrence: `t = (n & 1) ^ prev_t` pattern
 *   3. Accumulation of indices where T(n)==1
 *
 * Test: Compute T(0..31), count how many equal 1, sum those indices.
 *
 * In [0..31]: exactly 16 values have odd popcount (T=1).
 * Indices: 1,2,4,7,8,11,13,14,16,19,21,22,25,26,28,31 — sum=248
 *
 * g_result = (32<<16)|(16<<8)|248 = 0x002010F8
 * Bytes: 0x20=32, 0x10=16, 0xF8=248 — all distinct and non-zero.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TM_N 32u

/* Thue-Morse value: parity of popcount(n) */
static uint32_t thue_morse(uint32_t n)
{
    uint32_t x = n;
    x ^= (x >> 16);
    x ^= (x >> 8);
    x ^= (x >> 4);
    x ^= (x >> 2);
    x ^= (x >> 1);
    return x & 1u;
}

/* Recurrence version for variety */
static uint32_t thue_morse_rec(uint32_t n)
{
    uint32_t t = 0u;
    while (n > 0u) {
        t ^= (n & 1u);
        n >>= 1;
    }
    return t;
}

void test_thue_morse(void)
{
    uint32_t count = 0u;
    uint32_t sum   = 0u;
    uint32_t i;

    for (i = 0u; i < TM_N; i++) {
        if (thue_morse(i)) {
            count++;
            sum += i;
        }
    }

    /* Verify recurrence version agrees with bit-trick version */
    uint32_t agree = 0u;
    for (i = 0u; i < TM_N; i++) {
        if (thue_morse(i) == thue_morse_rec(i)) agree++;
    }
    (void)agree; /* should be TM_N */

    /* count=16=0x10, sum=248=0xF8
     * g_result = (32<<16)|(16<<8)|248 = 0x002010F8
     * Bytes: 0x20, 0x10, 0xF8 — distinct and non-zero */
    g_result = (TM_N << 16) | (count << 8) | (sum & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_thue_morse();
    for (;;);
}
