/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Balloon Burst (Interval DP) fixture.
 *
 * The balloon burst problem: given n balloons with values a[0..n-1] and
 * virtual boundary balloons of value 1 on each end, choose the order to
 * burst them. Bursting balloon k between boundaries l and r earns
 * a[l]*a[k]*a[r] coins. Maximize total coins.
 *
 * Interval DP recurrence (padded array p = [1, a[0], ..., a[n-1], 1]):
 *   dp[l][r] = max_k in (l+1..r-1): p[l]*p[k]*p[r] + dp[l][k] + dp[k][r]
 *   (k is the LAST balloon to be burst in the open interval (l, r))
 *
 * Distinctive decompiler idioms:
 *   1. `if (b_dp[l][r] >= 0) return b_dp[l][r]` — memoization guard
 *   2. `p[l]*p[k]*p[r] + b_solve(l,k) + b_solve(k,r)` — three-factor product
 *   3. dp indexed on OPEN intervals: k ranges l+1 to r-1 (inclusive)
 *   4. Padded boundary: p[0]=1, p[n+1]=1
 *
 * Test: n=3 balloons, a=[3,1,5] → padded p=[1,3,1,5,1]
 *
 * Optimal strategy: burst center balloon 1 last → 1*1*1=1 leftover times:
 *   burst balloon 0 (a=3): boundary 1, right 1 → 1*3*1=3... wait.
 *   Optimal: burst a[1]=1 LAST in (0,4): cost=p[0]*p[2]*p[4]=1*1*1=1
 *            + burst a[0]=3 LAST in (0,2): cost=p[0]*p[1]*p[2]=1*3*1=3
 *            + burst a[2]=5 LAST in (2,4): cost=p[2]*p[3]*p[4]=1*5*1=5
 *   Nope, let's compute directly:
 *   dp[0][4] = max:
 *     k=1: 1*3*1 + dp[0][1] + dp[1][4] = 3 + 0 + 30 = 33
 *     k=2: 1*1*1 + dp[0][2] + dp[2][4] = 1 + 3 + 5 = 9
 *     k=3: 1*5*1 + dp[0][3] + dp[3][4] = 5 + 30 + 0 = 35  ← best
 *   dp[0][4] = 35
 *
 * n_balloons   = 3
 * max_coins    = 35 = 0x23
 * padded_len   = 5  = 0x05
 *
 * g_result = (n_balloons << 16) | (max_coins << 8) | padded_len = 0x00032305
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BB_N  3
#define BB_P  (BB_N + 2)   /* padded length = 5 */

static int b_dp[BB_P][BB_P];
static int b_p[BB_P];

static int b_solve(int l, int r)
{
    if (r - l < 2) return 0;
    if (b_dp[l][r] >= 0) return b_dp[l][r];
    int best = 0;
    for (int k = l + 1; k < r; k++) {
        int coins = b_p[l] * b_p[k] * b_p[r]
                  + b_solve(l, k) + b_solve(k, r);
        if (coins > best) best = coins;
    }
    return (b_dp[l][r] = best);
}

void test_balloon_burst(void)
{
    static const int a[BB_N] = {3, 1, 5};

    /* Build padded array: 1, a[0], a[1], ..., a[n-1], 1 */
    b_p[0] = 1;
    for (int i = 0; i < BB_N; i++) b_p[i + 1] = a[i];
    b_p[BB_N + 1] = 1;

    /* Initialise memo to -1 */
    for (int i = 0; i < BB_P; i++)
        for (int j = 0; j < BB_P; j++)
            b_dp[i][j] = -1;

    int max_coins = b_solve(0, BB_P - 1);  /* 35 */

    g_result = ((uint32_t)BB_N      << 16)
             | ((uint32_t)max_coins << 8)
             | ((uint32_t)BB_P      & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_balloon_burst();
    for (;;);
}
