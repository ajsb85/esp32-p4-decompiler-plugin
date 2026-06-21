/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Perfect Squares (min count) fixture.
 *
 * Finds the minimum number of perfect square numbers that sum to n,
 * using bottom-up DP: dp[0]=0; for each i: dp[i]=min(dp[i-j*j]+1) for j*j<=i.
 *
 * Distinctive decompiler idioms:
 *   1. `for j=1; j*j<=i; j++` — enumerate square numbers
 *   2. `dp[i] = min(dp[i], dp[i-j*j]+1)` — relaxation
 *   3. `dp[0]=0; dp[i]=INF init` — standard DP init
 *
 * Test cases:
 *   n=12 → 3  (4+4+4)
 *   n=13 → 2  (4+9)
 *   n=7  → 4  (4+1+1+1)
 *   n=9  → 1  (9)
 *
 * n_tests=4, sum=10, xor=3^2^4^1=4
 * g_result = (4 << 16) | (10 << 8) | 4 = 0x00040A04
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PS_INF 9999

static int ps_dp[14];

static int min_perfect_squares(int n)
{
    for (int i = 0; i <= n; i++) ps_dp[i] = PS_INF;
    ps_dp[0] = 0;
    for (int i = 1; i <= n; i++)
        for (int j = 1; j * j <= i; j++)
            if (ps_dp[i - j * j] + 1 < ps_dp[i])
                ps_dp[i] = ps_dp[i - j * j] + 1;
    return ps_dp[n];
}

void test_perfect_squares(void)
{
    int tests[4] = {12, 13, 7, 9};
    int mins[4];
    for (int i = 0; i < 4; i++)
        mins[i] = min_perfect_squares(tests[i]);

    uint32_t sum = (uint32_t)(mins[0] + mins[1] + mins[2] + mins[3]); /* 10 */
    uint32_t xr  = (uint32_t)(mins[0] ^ mins[1] ^ mins[2] ^ mins[3]); /* 4 */

    g_result = (4u << 16) | ((sum & 0xFFu) << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_perfect_squares();
    for (;;);
}
