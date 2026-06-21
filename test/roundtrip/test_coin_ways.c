/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Coin change (count ways) fixture.
 *
 * Count distinct ways to make change for a target amount using unbounded coins.
 * Classic unbounded knapsack DP: dp[0]=1; for each coin, inner loop adds ways.
 *
 * Distinctive decompiler idioms:
 *   1. `dp[0] = 1` — base case: exactly 1 way to make amount 0
 *   2. `for(coin) for(j=coin..amount) dp[j] += dp[j-coin]` — unbounded knapsack
 *   3. Query result at dp[amount] after all coins processed
 *
 * Coins: {1, 2, 3}  Amounts: {4, 6, 10}
 * ways(4) = 4  (1+1+1+1; 1+1+2; 2+2; 1+3)
 * ways(6) = 7
 * ways(10)= 14
 *
 * n_queries  = 3
 * sum_ways   = 25  (0x19)
 * xor_ways   = 4^7^14 = 13  (0x0D)
 *
 * g_result = (n << 16) | (sum_ways << 8) | xor_ways = 0x0003190D
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CW_AMT 10
#define CW_NC  3

static const int cw_coins[CW_NC]  = {1, 2, 3};
static const int cw_amts[3]       = {4, 6, 10};
static int cw_dp[CW_AMT + 1];

void test_coin_ways(void)
{
    for (int i = 0; i <= CW_AMT; i++) cw_dp[i] = 0;
    cw_dp[0] = 1;

    for (int ci = 0; ci < CW_NC; ci++)
        for (int j = cw_coins[ci]; j <= CW_AMT; j++)
            cw_dp[j] += cw_dp[j - cw_coins[ci]];

    uint32_t cw_sum = 0, cw_xor = 0;
    for (int i = 0; i < 3; i++) {
        uint32_t w = (uint32_t)cw_dp[cw_amts[i]];
        cw_sum += w;
        cw_xor ^= w;
    }

    g_result = (3u << 16) | ((cw_sum & 0xFFu) << 8) | (cw_xor & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_coin_ways();
    for (;;);
}
