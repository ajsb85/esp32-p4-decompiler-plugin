/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Partition Equal Subset Sum fixture.
 *
 * Determines whether an array can be split into two subsets with equal sums.
 * Uses 0/1 knapsack boolean DP: dp[0]=1; for each num: for j=target downto num:
 *   dp[j] |= dp[j-num]
 *
 * Distinctive decompiler idioms:
 *   1. `total = sum(arr); if(total%2!=0) not possible`
 *   2. `for each num: for j=target downto num: dp[j]|=dp[j-num]` — 0/1 knapsack
 *   3. `return dp[target]` — final answer
 *
 * Test cases:
 *   1. {1,5,11,5}:   total=22, target=11, achievable={1,5,5} → 1 (hit: 11)
 *   2. {1,2,3,5}:    total=11 (odd) → impossible → 0
 *   3. {2,3,5,6,8,10}: total=34, target=17, achievable={2,5,10} → 1 (hit: 17)
 *
 * metric_a = sum of achieved targets = 11+17 = 28 = 0x1C
 * metric_b = n_false = 1
 *
 * g_result = (3 << 16) | (28 << 8) | 1 = 0x00031C01
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PES_MAXN  8
#define PES_MAXT 64

static int pes_dp[PES_MAXT + 1];

static int partition_equal_sum(const int *arr, int n)
{
    int total = 0;
    for (int i = 0; i < n; i++) total += arr[i];
    if (total % 2 != 0) return 0;

    int target = total / 2;
    for (int j = 0; j <= target; j++) pes_dp[j] = 0;
    pes_dp[0] = 1;

    for (int i = 0; i < n; i++)
        for (int j = target; j >= arr[i]; j--)
            if (pes_dp[j - arr[i]]) pes_dp[j] = 1;

    return pes_dp[target];
}

void test_partition_equal_sum(void)
{
    const int a1[4] = {1, 5, 11, 5};
    const int a2[4] = {1, 2,  3, 5};
    const int a3[6] = {2, 3,  5, 6, 8, 10};

    int r1 = partition_equal_sum(a1, 4);
    int r2 = partition_equal_sum(a2, 4);
    int r3 = partition_equal_sum(a3, 6);

    /* metric_a: sum of targets achieved (11 + 17) */
    int target1 = r1 ? (22 / 2) : 0;
    int target3 = r3 ? (34 / 2) : 0;
    uint32_t metric_a = (uint32_t)(target1 + target3); /* 28 */
    /* metric_b: count of false results */
    uint32_t metric_b = (uint32_t)((1 - r1) + (1 - r2) + (1 - r3)); /* 1 */

    g_result = (3u << 16) | ((metric_a & 0xFFu) << 8) | (metric_b & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_partition_equal_sum();
    for (;;);
}
