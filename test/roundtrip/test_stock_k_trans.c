/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Stock buy/sell with at most 2 transactions fixture.
 *
 * Classic DP state machine: track buy1/sell1/buy2/sell2 as running optima.
 * One forward pass over prices updates all four states simultaneously.
 *
 * Distinctive decompiler idioms:
 *   1. `buy1 = max(buy1, -price)` — track cheapest buy so far
 *   2. `sell1 = max(sell1, buy1 + price)` — best profit after 1st sell
 *   3. `buy2 = max(buy2, sell1 - price)` — best net after 2nd buy (uses 1st profit)
 *   4. `sell2 = max(sell2, buy2 + price)` — best profit after 2nd sell
 *
 * Prices: {3, 3, 5, 0, 0, 3, 1, 4}
 * Optimal: buy@0, sell@3, buy@1, sell@4 → profit = 3 + 3 = 6
 *
 * n_days     = 8
 * max_profit = 6
 * xor_prices = 3^3^5^0^0^3^1^4 = 3
 *
 * g_result = (n_days << 16) | (max_profit << 8) | xor_prices = 0x00080603
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SK_N 8

static const int sk_prices[SK_N] = {3, 3, 5, 0, 0, 3, 1, 4};

static int sk_max(int a, int b) { return a > b ? a : b; }

void test_stock_k_trans(void)
{
    int buy1 = -(1 << 30), sell1 = -(1 << 30);
    int buy2 = -(1 << 30), sell2 = -(1 << 30);
    uint32_t xp = 0;

    for (int i = 0; i < SK_N; i++) {
        int p = sk_prices[i];
        buy1  = sk_max(buy1,  -p);
        sell1 = sk_max(sell1, buy1  + p);
        buy2  = sk_max(buy2,  sell1 - p);
        sell2 = sk_max(sell2, buy2  + p);
        xp ^= (uint32_t)p;
    }

    g_result = ((uint32_t)SK_N << 16) | ((uint32_t)sell2 << 8) | (xp & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_stock_k_trans();
    for (;;);
}
