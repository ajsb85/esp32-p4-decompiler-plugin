/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Derangements (subfactorial) fixture.
 *
 * Counts permutations with no fixed point using the recurrence:
 * D(0)=1, D(1)=0, D(n)=(n-1)*(D(n-1)+D(n-2))
 *
 * Distinctive decompiler idioms:
 *   1. `dp[n] = (n-1) * (dp[n-1] + dp[n-2])` — recurrence
 *   2. `dp[0]=1; dp[1]=0` — base cases (not DP array init with 0)
 *   3. `sum XOR accumulate` — result encoding
 *
 * Test cases:
 *   D(3)=2, D(4)=9, D(5)=44
 *   sum=2+9+44=55=0x37, xor=2^9^44=39=0x27
 *
 * g_result = (3 << 16) | (55 << 8) | 39 = 0x00033727
 */
#include <stdint.h>

volatile uint32_t g_result;

#define DR_N 6

static uint32_t dr_dp[DR_N];

void test_derange(void)
{
    dr_dp[0] = 1;
    dr_dp[1] = 0;
    for (int n = 2; n < DR_N; n++)
        dr_dp[n] = (uint32_t)(n - 1) * (dr_dp[n-1] + dr_dp[n-2]);

    uint32_t d3 = dr_dp[3]; /* 2  */
    uint32_t d4 = dr_dp[4]; /* 9  */
    uint32_t d5 = dr_dp[5]; /* 44 */

    uint32_t sum = (d3 + d4 + d5) & 0xFFu; /* 55 */
    uint32_t xr  = d3 ^ d4 ^ d5;           /* 39 */

    g_result = (3u << 16) | (sum << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_derange();
    for (;;);
}
