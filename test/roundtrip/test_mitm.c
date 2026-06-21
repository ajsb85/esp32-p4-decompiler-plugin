/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Meet-in-the-Middle Subset Sum Count fixture.
 *
 * Counts subsets of {1,2,...,8} that sum to target T=17 by splitting
 * into left half {1,2,3,4} and right half {5,6,7,8}.
 *
 * Algorithm:
 *   1. Enumerate 2^(n/2) subset sums for each half.
 *   2. Sort one half's sums.
 *   3. For each right sum r, binary-search for (T-r) in sorted left sums.
 *   4. Accumulate match counts.
 *
 * Distinctive decompiler idioms:
 *   1. `for (mask=0; mask < (1<<HALF); mask++)` — enumerate all 2^half subsets
 *   2. `for (b=0; b<HALF; b++) if (mask>>b & 1) s += arr[b]` — subset sum from mask
 *   3. `isort(left_sums, 1<<HALF)` — sort enumerated sums (for binary search)
 *   4. Lower-bound/upper-bound binary search pair to count occurrences
 *   5. `if (need >= 0) cnt += count(left_sums, need)` — guarded lookup
 *
 * Left half {1,2,3,4}: 16 subset sums, range [0,10]
 * Right half {5,6,7,8}: 16 subset sums, range [0,26]
 *
 * Pairs summing to 17:
 *   sumL=2→sumR=15: {2}&{7,8}                     → 1
 *   sumL=3→sumR=14: {3},{1,2}&{6,8}               → 2
 *   sumL=4→sumR=13: {4},{1,3}&{5,8},{6,7}         → 4
 *   sumL=5→sumR=12: {1,4},{2,3}&{5,7}             → 2
 *   sumL=6→sumR=11: {2,4},{1,2,3}&{5,6}           → 2
 *   sumL=9→sumR=8:  {2,3,4}&{8}                   → 1
 *   sumL=10→sumR=7: {1,2,3,4}&{7}                 → 1
 *   Total = 13 = 0x0D
 *
 * n_elements  = 8  = 0x08
 * target      = 17 = 0x11
 * n_subsets   = 13 = 0x0D
 *
 * g_result = (n_elements << 16) | (target << 8) | n_subsets = 0x08110D
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MITM_N 8
#define MITM_H 4   /* half */
#define MITM_T 17  /* target sum */

static const int mitm_a[MITM_N] = {1, 2, 3, 4, 5, 6, 7, 8};
static int mitm_lsums[1 << MITM_H];
static int mitm_rsums[1 << MITM_H];

static void mitm_isort(int *a, int n)
{
    for (int i = 1; i < n; i++) {
        int k = a[i], j = i - 1;
        while (j >= 0 && a[j] > k) { a[j+1] = a[j]; j--; }
        a[j+1] = k;
    }
}

static int mitm_count(int *a, int n, int v)
{
    int lo = 0, hi = n;
    while (lo < hi) { int m = (lo+hi)/2; if (a[m] < v) lo=m+1; else hi=m; }
    int lb = lo;
    lo = 0; hi = n;
    while (lo < hi) { int m = (lo+hi)/2; if (a[m] <= v) lo=m+1; else hi=m; }
    return lo - lb;
}

void test_mitm(void)
{
    int half = 1 << MITM_H;  /* 16 */

    for (int mask = 0; mask < half; mask++) {
        int s = 0;
        for (int b = 0; b < MITM_H; b++) if (mask >> b & 1) s += mitm_a[b];
        mitm_lsums[mask] = s;
    }
    for (int mask = 0; mask < half; mask++) {
        int s = 0;
        for (int b = 0; b < MITM_H; b++) if (mask >> b & 1) s += mitm_a[MITM_H + b];
        mitm_rsums[mask] = s;
    }

    mitm_isort(mitm_lsums, half);

    int cnt = 0;
    for (int i = 0; i < half; i++) {
        int need = MITM_T - mitm_rsums[i];
        if (need >= 0) cnt += mitm_count(mitm_lsums, half, need);
    }
    /* cnt = 13 */

    g_result = ((uint32_t)MITM_N << 16)
             | ((uint32_t)MITM_T << 8)
             | ((uint32_t)cnt & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_mitm();
    for (;;);
}
