/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Increasing Subsequence (patience sort) fixture.
 *
 * O(n log n) LIS length via patience sorting:
 * Maintain a "piles" array where piles[k] is the smallest tail element among
 * all increasing subsequences of length k+1.  For each new element, binary
 * search for the leftmost pile-top ≥ value and replace it (or extend with a
 * new pile if the element is larger than all pile tops).
 *
 * Input (n=11):
 *   {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5}
 *
 * Patience sort trace (piles evolve as):
 *   [3] → [1] → [1,4] → [1,4] → [1,4,5] → [1,4,5,9]
 *   → [1,2,5,9] → [1,2,5,6] → [1,2,5,6] → [1,2,3,6] → [1,2,3,5]
 *
 * LIS length = 4 (number of final piles)
 * Final pile tops: {1, 2, 3, 5}
 *   xor_piles = 1^2^3^5 = 5
 *
 * g_result = (n << 16) | (lis_len << 8) | xor_piles = 0x000B0405
 *
 * Recognizable decompiler idioms:
 *   while (lo < hi) { m=(lo+hi)/2; if (piles[m] < v) lo=m+1; else hi=m; }
 *   piles[lo] = v; if (lo == np) np++;  ← extend or replace
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── O(n log n) LIS length ───────────────────────────────────────────────── */

#define LIS_N 11

static int lis_piles[LIS_N];

static int lis_length(const int *arr, int n)
{
    int np = 0;   /* number of active piles */

    for (int i = 0; i < n; i++) {
        int v  = arr[i];
        int lo = 0, hi = np;

        /* Binary search: leftmost pile-top >= v */
        while (lo < hi) {
            int m = (lo + hi) / 2;
            if (lis_piles[m] < v)
                lo = m + 1;
            else
                hi = m;
        }
        lis_piles[lo] = v;
        if (lo == np)
            np++;
    }
    return np;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_lis(void)
{
    static const int arr[LIS_N] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5};
    int len = lis_length(arr, LIS_N);   /* = 4 */

    uint32_t xor_p = 0;
    for (int i = 0; i < len; i++)
        xor_p ^= (uint32_t)lis_piles[i];   /* = 5 */

    g_result = ((uint32_t)LIS_N << 16)
             | ((uint32_t)len << 8)
             | (xor_p & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_lis();
    for (;;);
}
