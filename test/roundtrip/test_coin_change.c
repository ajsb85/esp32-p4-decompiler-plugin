/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Coin change (minimum coins) DP round-trip fixture.
 *
 * Classic 1D bottom-up DP: dp[i] = minimum number of coins to make amount i.
 *
 *   dp[0] = 0
 *   for i in 1..W:
 *     for each coin c: if i >= c: dp[i] = min(dp[i], dp[i-c]+1)
 *
 * Denominations: {1, 5, 12, 25}
 * Three target queries: {11, 14, 30}
 *
 * DP results:
 *   dp[11] = 3  (5 + 5 + 1)
 *   dp[14] = 3  (12 + 1 + 1)
 *   dp[30] = 2  (25 + 5)
 *
 *   sum   = 3 + 3 + 2 = 8
 *   xor   = 3 ^ 3 ^ 2 = 2
 *   n_coins = 4 (number of denominations)
 *
 * g_result = (n_coins << 16) | (sum << 8) | xor = 0x00040802
 *
 * Recognizable decompiler idioms:
 *   for (c = coin[j]; i >= c; ...): dp[i] = min(dp[i], dp[i-c]+1)
 *   dp[0] = 0; dp[i] = BIG_VAL initialisation
 *   reverse inner loop over denominations
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Coin change ────────────────────────────────────────────────────────────── */

#define CC_COINS   4
#define CC_LIMIT  30

static int cc_dp[CC_LIMIT + 1];

static void coin_change_dp(const int *coins, int nc, int limit)
{
    cc_dp[0] = 0;
    for (int i = 1; i <= limit; i++) {
        cc_dp[i] = CC_LIMIT + 1;   /* sentinel "infinity" */
        for (int j = 0; j < nc; j++) {
            if (i >= coins[j] && cc_dp[i - coins[j]] + 1 < cc_dp[i])
                cc_dp[i] = cc_dp[i - coins[j]] + 1;
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_coin_change(void)
{
    static const int coins[CC_COINS]   = {1, 5, 12, 25};
    static const int targets[3]        = {11, 14, 30};

    coin_change_dp(coins, CC_COINS, CC_LIMIT);

    uint32_t sum_c = 0, xor_c = 0;
    for (int k = 0; k < 3; k++) {
        uint32_t v = (uint32_t)cc_dp[targets[k]];
        sum_c += v;
        xor_c ^= v;
    }

    g_result = ((uint32_t)CC_COINS << 16)
             | (sum_c << 8)
             | (xor_c & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_coin_change();
    for (;;);
}
