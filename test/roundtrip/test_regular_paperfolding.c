/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Regular Paper Folding sequence fixture.
 *
 * The regular paper folding (dragon curve) sequence P(n) for n >= 1:
 *   Fold a strip of paper in half repeatedly, always the same direction,
 *   then unfold and read the sequence of valley (1) and mountain (0) folds.
 *
 * Formula: Write n = 2^k * m where m is odd.
 *   P(n) = 1 if m ≡ 1 (mod 4)
 *   P(n) = 0 if m ≡ 3 (mod 4)
 *
 * This is equivalent to: strip trailing zeros from n, get odd part m,
 * then check m mod 4.
 *
 * Sequence P(1..16): 1,1,0,1,1,0,0,1,1,1,0,0,1,0,0,1
 *
 * Distinctive decompiler idioms:
 *   1. 2-adic valuation: `while ((n & 1) == 0) n >>= 1`
 *   2. Modulo-4 branch: `return (m % 4 == 1) ? 1 : 0`
 *   3. Loop accumulating P(n) values
 *
 * Test: Compute P(1..32), count P(n)==1, XOR those indices.
 *
 * In [1..32]: count=17=0x11, XOR of indices with P=1 = 40=0x28
 *
 * g_result = (32<<16)|(17<<8)|40 = 0x00201128
 * Bytes: 0x20=32, 0x11=17, 0x28=40 — all distinct and non-zero.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PF_N 32u

/* Regular paper folding: strip trailing zeros from n to get odd part m,
 * return 1 if m % 4 == 1, else 0. */
static uint32_t paperfolding(uint32_t n)
{
    if (n == 0u) return 0u;    /* undefined at n=0, return 0 */
    uint32_t m = n;
    while ((m & 1u) == 0u) {
        m >>= 1;               /* remove factors of 2 */
    }
    /* m is now the odd part of n */
    return ((m & 3u) == 1u) ? 1u : 0u;
}

void test_regular_paperfolding(void)
{
    uint32_t count   = 0u;
    uint32_t xor_idx = 0u;
    uint32_t i;

    for (i = 1u; i <= PF_N; i++) {
        if (paperfolding(i)) {
            count++;
            xor_idx ^= i;
        }
    }

    /* count=17=0x11, xor_idx=40=0x28
     * g_result = (32<<16)|(17<<8)|40 = 0x00201128
     * Bytes: 0x20, 0x11, 0x28 — distinct and non-zero */
    g_result = (PF_N << 16) | (count << 8) | (xor_idx & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_regular_paperfolding();
    for (;;);
}
