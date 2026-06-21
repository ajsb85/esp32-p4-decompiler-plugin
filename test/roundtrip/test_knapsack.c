/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — 0/1 Knapsack DP round-trip fixture.
 *
 * Classic 0/1 knapsack solved with a 1D bottom-up DP table (reverse
 * inner iteration prevents counting an item more than once).
 *
 * Items: (weight, value) pairs
 *   item 0: w=2, v=3
 *   item 1: w=3, v=4
 *   item 2: w=4, v=5
 *   item 3: w=5, v=6
 *
 * Knapsack capacity W = 8.
 *
 * DP trace (1D, processed in item order):
 *   After item 0: dp = [0, 0, 3, 3, 3, 3, 3, 3, 3]
 *   After item 1: dp = [0, 0, 3, 4, 4, 7, 7, 7, 7]
 *   After item 2: dp = [0, 0, 3, 4, 5, 7, 8, 9, 9]
 *   After item 3: dp = [0, 0, 3, 4, 5, 7, 8, 9,10]
 *
 * Optimal value = dp[8] = 10  (items 1+3: w=3+5=8, v=4+6=10)
 *
 * Recognizable decompiler idioms:
 *   for j = W downto w[i]: dp[j] = max(dp[j], dp[j-w[i]] + v[i])
 *   reverse inner loop (j going downward) prevents double-counting.
 *
 * g_result = (n_items << 16) | (capacity << 8) | optimal_value
 *           = (4 << 16) | (8 << 8) | 10 = 0x0004080A
 */
#include <stdint.h>

volatile uint32_t g_result;

#define N_ITEMS  4
#define CAPACITY 8

/* ── 0/1 Knapsack solver ─────────────────────────────────────────────────── */

static int ks_dp[CAPACITY + 1]; /* dp[j] = max value achievable with capacity j */

static int knapsack(const int *w, const int *v, int n, int cap)
{
    for (int j = 0; j <= cap; j++)
        ks_dp[j] = 0;

    for (int i = 0; i < n; i++) {
        /* Reverse iteration: prevents using item i more than once. */
        for (int j = cap; j >= w[i]; j--) {
            int with_item = ks_dp[j - w[i]] + v[i];
            if (with_item > ks_dp[j])
                ks_dp[j] = with_item;
        }
    }

    return ks_dp[cap];
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_knapsack(void)
{
    static const int weights[N_ITEMS] = {2, 3, 4, 5};
    static const int values[N_ITEMS]  = {3, 4, 5, 6};

    int opt = knapsack(weights, values, N_ITEMS, CAPACITY);

    g_result = ((uint32_t)N_ITEMS   << 16)
             | ((uint32_t)CAPACITY  << 8)
             | ((uint32_t)opt & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_knapsack();
    for (;;);
}
