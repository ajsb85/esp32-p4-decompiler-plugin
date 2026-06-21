/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Bitmask enumeration fixture.
 *
 * Enumerates all 2^n subsets of an array via bitmask.
 * For each subset computes its element sum and identifies:
 *   - count of subsets whose sum is divisible by k
 *   - maximum such sum
 *
 * Distinctive decompiler idioms:
 *   for (mask = 0; mask < (1 << n); mask++) {
 *       for (b = 0; b < n; b++)
 *           if (mask & (1 << b)) sum += items[b];
 *       if (sum % k == 0) { count++; if (sum > max_sum) max_sum = sum; }
 *   }
 *
 * Key decompiler signals:
 *   1. `1 << n` or `1u << n`  ← full set bound
 *   2. `mask & (1 << b)`      ← bit test for element membership
 *   3. `sum % k == 0`         ← divisibility filter
 *
 * Input: items = {2, 3, 7, 5}, n=4, k=3
 *
 * Subsets with sum divisible by 3:
 *   {}         sum=0  ✓
 *   {3}        sum=3  ✓
 *   {2,7}      sum=9  ✓
 *   {7,5}      sum=12 ✓
 *   {2,3,7}    sum=12 ✓
 *   {3,7,5}    sum=15 ✓
 *
 * count   = 6
 * max_sum = 15  (0x0F)
 *
 * g_result = (n << 16) | (count << 8) | max_sum = 0x0004060F
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Bitmask Enumeration ──────────────────────────────────────────────────── */

#define BM_N  4
#define BM_K  3

static void bitmask_enum(const int *items, int n, int k, int *count_out, int *max_sum_out)
{
    int count = 0, max_sum = -1;
    int total = 1 << n;
    for (int mask = 0; mask < total; mask++) {
        int sum = 0;
        for (int b = 0; b < n; b++)
            if (mask & (1 << b)) sum += items[b];
        if (sum % k == 0) {
            count++;
            if (sum > max_sum) max_sum = sum;
        }
    }
    *count_out   = count;
    *max_sum_out = max_sum;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_bitmask_enum(void)
{
    static const int items[BM_N] = {2, 3, 7, 5};
    int count, max_sum;

    bitmask_enum(items, BM_N, BM_K, &count, &max_sum);
    /* count=6, max_sum=15 */

    g_result = ((uint32_t)BM_N << 16)
             | ((uint32_t)count << 8)
             | (uint32_t)max_sum;
}

__attribute__((noreturn)) void _start(void)
{
    test_bitmask_enum();
    for (;;);
}
