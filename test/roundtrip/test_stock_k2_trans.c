/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Stock with At Most k=2 Transactions (DP).
 *
 * dp[t][d] = max profit with at most t transactions through day d.
 * Key trick: max_so_far = max(dp[t-1][d-1] - price[d]) tracks best buy basis.
 *
 * Distinctive decompiler idioms:
 *   1. `max_so_far = -prices[0]` — initialize with "bought on day 0"
 *   2. `dp[t][d]=dp[t][d-1]; if(prices[d]+max_so_far>dp[t][d]) dp[t][d]=...`
 *   3. `if(dp[t-1][d-1]-prices[d]>max_so_far) max_so_far=...` — update buy basis
 *
 * Prices: {3,2,6,5,0,3}, k=2, n=6
 * Optimal: buy@2 sell@6 (+4), buy@0 sell@3 (+3) → profit=7
 *
 * g_result = (n<<16)|(max_profit<<8)|k = 0x00060702
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_stock_k2_trans(void)
{
    static const int prices[6] = {3, 2, 6, 5, 0, 3};
    int n = 6, k = 2;
    static int dp[3][6];
    int t, d;

    for (t = 0; t <= k; t++) dp[t][0] = 0;
    for (d = 0; d < n; d++) dp[0][d] = 0;

    for (t = 1; t <= k; t++) {
        int max_so_far = -prices[0];
        for (d = 1; d < n; d++) {
            dp[t][d] = dp[t][d-1];
            if (prices[d] + max_so_far > dp[t][d])
                dp[t][d] = prices[d] + max_so_far;
            if (dp[t-1][d-1] - prices[d] > max_so_far)
                max_so_far = dp[t-1][d-1] - prices[d];
        }
    }

    int profit = dp[k][n-1];
    /* profit=7, n=6, k=2 */
    g_result = ((uint32_t)n << 16)
             | ((uint32_t)profit << 8)
             | (uint32_t)k;
}

__attribute__((noreturn)) void _start(void)
{
    test_stock_k2_trans();
    for (;;);
}
