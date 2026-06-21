/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Coin Change Minimum (1D DP).
 *
 * Finds the minimum number of coins needed to reach a target sum.
 * dp[i] = min coins to make amount i; initialized to INF, dp[0]=0.
 *
 * Distinctive decompiler idioms:
 *   1. `for(i=0;i<=t;i++) dp[i]=INF; dp[0]=0` — DP initialization
 *   2. `for(i=1;i<=t;i++) for(j<n) if(coins[j]<=i&&dp[i-coins[j]]+1<dp[i])`
 *   3. `dp[i]=dp[i-coins[j]]+1` — take this coin, one more coin used
 *   4. `r=(dp[t]==INF)?-1:dp[t]` — -1 means impossible
 *
 * Test 1: coins={1,5,6,9}, target=11 → min=2 (5+6)
 * Test 2: coins={1,2,5}, target=11 → min=3 (5+5+1)
 * n_coin_sets=3, targets_sum=22=0x16, r1^r3=2^3=1
 *
 * g_result = (3<<16)|(targets_sum&0xFF<<8)|(r1^r3) = 0x00031601
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_coin_change_min(void)
{
    static const int coins1[4] = {1, 5, 6, 9};
    static const int coins3[3] = {1, 2, 5};
    int dp[12], i, j;
    const int INF = 999;

    /* coins1, target=11 */
    for (i = 0; i <= 11; i++) dp[i] = INF;
    dp[0] = 0;
    for (i = 1; i <= 11; i++)
        for (j = 0; j < 4; j++)
            if (coins1[j] <= i && dp[i - coins1[j]] + 1 < dp[i])
                dp[i] = dp[i - coins1[j]] + 1;
    int r1 = (dp[11] == INF) ? -1 : dp[11];

    /* coins3, target=11 */
    for (i = 0; i <= 11; i++) dp[i] = INF;
    dp[0] = 0;
    for (i = 1; i <= 11; i++)
        for (j = 0; j < 3; j++)
            if (coins3[j] <= i && dp[i - coins3[j]] + 1 < dp[i])
                dp[i] = dp[i - coins3[j]] + 1;
    int r3 = (dp[11] == INF) ? -1 : dp[11];

    /* r1=2, r3=3; targets_sum=11+11=22=0x16; r1^r3=1 */
    g_result = (3u << 16)
             | (((uint32_t)(11 + 11) & 0xFFu) << 8)
             | (uint32_t)(r1 ^ r3);
}

__attribute__((noreturn)) void _start(void)
{
    test_coin_change_min();
    for (;;);
}
