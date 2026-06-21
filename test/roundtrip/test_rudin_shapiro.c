/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Rudin-Shapiro Sequence fixture.
 *
 * Rudin-Shapiro sequence r(n): count consecutive "11" patterns in binary(n).
 * r(n) = (-1)^(number of 11-bit pairs in binary n), but we use +1/-1 mapped to 0/1.
 *
 * Recurrence:
 *   R(0)=1, R(1)=1
 *   R(2n)   = R(n)
 *   R(2n+1) = R(n) * (-1)^n   but mapped as:
 *
 * Simpler bit-count definition:
 *   Count pairs of consecutive 1-bits in binary(n): if even → +1, if odd → -1
 *   We represent as 1 (positive) and 0 (negative).
 *
 * Distinctive decompiler idioms:
 *   1. Consecutive-bit-pair counting: `while (n) { if ((n&3)==3) pairs++; n>>=1; }`
 *   2. Parity check on pair count: `sign = pairs & 1`
 *   3. Prefix sum / running total of signs
 *
 * Test: Compute R(0..31) — count positives (+1), sum them.
 *
 * For N=32: pos_count=20, neg_count=12.
 * sum_pos = 0+1+2+4+5+7+8+9+10+14+16+17+18+20+21+23+27+28+29+31 = 270, mod 256 = 14?
 * Actually: 0+1+2+4+5+7+8+9+10+14+16+17+18+20+21+23+27+28+29+31 = 290, mod 256 = 34.
 *
 * g_result = (32<<16)|(20<<8)|34 = 0x00201422
 * Bytes: 0x20=32, 0x14=20, 0x22=34 — all distinct and non-zero.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define RS_N 32

/* Count consecutive 11-bit pairs in n */
static uint32_t rs_pair_count(uint32_t n)
{
    uint32_t pairs = 0u;
    while (n > 1u) {
        /* Check if bottom two bits are both 1 */
        if ((n & 3u) == 3u) pairs++;
        n >>= 1;
    }
    return pairs;
}

/* Rudin-Shapiro value: +1 if pair_count even, -1 if odd. Return 1 or 0. */
static uint32_t rudin_shapiro(uint32_t n)
{
    return (rs_pair_count(n) & 1u) == 0u ? 1u : 0u;
}

static uint32_t rs_prefix_sum(uint32_t limit)
{
    /* Sum of Rudin-Shapiro +1/-1 values (as 1/0) over [0..limit) */
    uint32_t s = 0u, i;
    for (i = 0u; i < limit; i++) {
        s += rudin_shapiro(i);
    }
    return s;
}

void test_rudin_shapiro(void)
{
    uint32_t pos_count = 0u;
    uint32_t sum_pos   = 0u;
    uint32_t i;

    for (i = 0u; i < RS_N; i++) {
        if (rudin_shapiro(i)) {
            pos_count++;
            sum_pos += i;   /* accumulate index sum instead of XOR to avoid cancellation */
        }
    }

    /* Also exercise prefix sum */
    uint32_t ps = rs_prefix_sum(RS_N);
    (void)ps; /* should equal pos_count */

    /* pos_count=20, sum_pos=290 mod 256=34=0x22
     * g_result = (32<<16)|(20<<8)|34 = 0x00201422
     * Bytes: 0x20, 0x14, 0x22 — distinct and non-zero */
    g_result = ((uint32_t)RS_N << 16) | (pos_count << 8) | (sum_pos & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_rudin_shapiro();
    for (;;);
}
