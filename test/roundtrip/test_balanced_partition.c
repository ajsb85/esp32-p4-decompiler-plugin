/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Balanced Partition (Equal Subset Sum variant).
 *
 * For each array, determines if it can be split into two subsets with equal sum.
 * Uses 1D DP (knapsack): dp[j]=1 iff subset summing to j is reachable.
 * If total sum is odd, partition is impossible.
 *
 * Distinctive decompiler idioms:
 *   1. `if(sum&1){bal=0;continue}` — odd sum short-circuit
 *   2. `dp[0]=1; for(i) for(j=t;j>=arr[i];j--) if(dp[j-arr[i]])dp[j]=1` — 0-1 knapsack
 *   3. `bal=dp[target]` — result: is target sum achievable?
 *
 * Arrays tested:
 *   {1,5,11,5}: sum=22, target=11 → can balance (5+6? no: 1+5+5=11) → yes
 *   {1,2,3,4,5}: sum=15 odd → no
 *   {2,2,2,2}: sum=8, target=4 → yes
 *   {3,1,1,2,2,1}: sum=10, target=5 → yes
 *
 * n_sets=4, balanced_count=3, sum_lens_of_balanced=4+4+6=14
 *
 * g_result = (4<<16)|(balanced_count<<8)|(sum_lens&0xFF) = 0x0004030E
 */
#include <stdint.h>

volatile uint32_t g_result;

__attribute__((optimize("O1")))
void test_balanced_partition(void)
{
    static const int a0[4] = {1, 5, 11, 5};
    static const int a1[5] = {1, 2, 3, 4, 5};
    static const int a2[4] = {2, 2, 2, 2};
    static const int a3[6] = {3, 1, 1, 2, 2, 1};
    static const int *arrs[4] = {a0, a1, a2, a3};
    static const int lens[4] = {4, 5, 4, 6};
    static int dp[31];
    int bal[4], s;

    for (s = 0; s < 4; s++) {
        const int *arr = arrs[s];
        int n = lens[s], sum = 0, i;
        for (i = 0; i < n; i++) sum += arr[i];
        if (sum & 1) { bal[s] = 0; continue; }
        int t = sum / 2;
        for (i = 0; i <= t; i++) dp[i] = 0;
        dp[0] = 1;
        for (i = 0; i < n; i++)
            for (int j = t; j >= arr[i]; j--)
                if (dp[j - arr[i]]) dp[j] = 1;
        bal[s] = dp[t];
    }

    int cnt = 0;
    uint32_t len_sum = 0;
    for (s = 0; s < 4; s++) {
        if (bal[s]) { cnt++; len_sum += (uint32_t)lens[s]; }
    }
    /* cnt=3, len_sum=4+4+6=14=0x0E */
    g_result = (4u << 16)
             | ((uint32_t)cnt << 8)
             | (len_sum & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_balanced_partition();
    for (;;);
}
