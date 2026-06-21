/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Subset sum boolean DP fixture.
 *
 * Standard 0/1 subset-sum DP: dp[j] = true iff some subset of items sums to j.
 * Key idiom: iterate items outer, amounts inner (reverse order for 0/1):
 *
 *   dp[0] = true;
 *   for each item v:
 *     for j = target downto v:
 *       dp[j] |= dp[j - v];
 *
 * Items (n=5): {3, 5, 2, 8, 7}   capacity limit = 12
 *
 * dp after all items (reachable sums ≤ 12):
 *   {0,0,1,1,0,1,0,1,1,1,1,1,1}  (indices 0..12)
 *   ^2,3,5,7,8,9,10,11,12 are reachable
 *
 * Three target queries: {10, 12, 11}
 *   dp[10] = 1 (2+8 or 3+7)
 *   dp[12] = 1 (5+7)
 *   dp[11] = 1 (3+8)
 *   count_found = 3
 *   xor_found   = 10 ^ 12 ^ 11 = 13 = 0x0D
 *   n = 5
 *
 * g_result = (n << 16) | (count_found << 8) | xor_found = 0x0005030D
 *
 * Recognizable decompiler idioms:
 *   for j = limit downto v: dp[j] |= dp[j-v]   ← 0/1 knapsack-style loop
 *   dp[0] = 1; dp[1..limit] = 0                 ← base initialisation
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Subset sum ────────────────────────────────────────────────────────────── */

#define SS_N      5
#define SS_LIMIT 12

static int ss_dp[SS_LIMIT + 1];

static void subset_sum_build(const int *items, int n)
{
    ss_dp[0] = 1;
    for (int i = 1; i <= SS_LIMIT; i++) ss_dp[i] = 0;

    for (int k = 0; k < n; k++) {
        int v = items[k];
        for (int j = SS_LIMIT; j >= v; j--)
            ss_dp[j] |= ss_dp[j - v];
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_subset_sum(void)
{
    static const int items[SS_N]   = {3, 5, 2, 8, 7};
    static const int targets[3]    = {10, 12, 11};

    subset_sum_build(items, SS_N);

    int count_found = 0;
    uint32_t xor_found = 0;
    for (int k = 0; k < 3; k++) {
        if (ss_dp[targets[k]]) {
            count_found++;
            xor_found ^= (uint32_t)targets[k];
        }
    }

    g_result = ((uint32_t)SS_N << 16)
             | ((uint32_t)count_found << 8)
             | (xor_found & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_subset_sum();
    for (;;);
}
