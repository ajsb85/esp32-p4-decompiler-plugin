/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — QuickSelect (Kth smallest) fixture.
 *
 * QuickSelect finds the k-th smallest element in O(n) average time.
 * Uses the same Lomuto partition as quicksort but recurses only into
 * the relevant half based on the pivot's final position.
 *
 * Distinctive idiom vs quicksort:
 *   after partition:
 *     if (pivot_idx == k) return arr[k];      ← early-exit on match
 *     else if (k < pivot_idx) hi = pivot_idx - 1;
 *     else                    lo = pivot_idx + 1;
 *
 * Lomuto partition (pivot = arr[hi]):
 *   i = lo - 1;
 *   for j = lo..hi-1: if arr[j] <= pivot: ++i, swap arr[i]↔arr[j]
 *   swap arr[i+1]↔arr[hi]; return i+1;
 *
 * Input (n=8): {7, 2, 1, 6, 5, 3, 4, 8}
 * Sorted:       {1, 2, 3, 4, 5, 6, 7, 8}
 *
 * Queries (0-indexed k):
 *   k=0 → 1   (minimum)
 *   k=3 → 4   (lower median)
 *   k=7 → 8   (maximum)
 *
 * sum of results = 1+4+8 = 13
 * xor of results = 1^4^8 = 13
 *
 * n      = 8
 * sum    = 13
 * xor    = 13
 *
 * g_result = (n << 16) | (sum << 8) | xor = 0x00080D0D
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── QuickSelect ──────────────────────────────────────────────────────────── */

#define QS_N 8

static int qs_arr[QS_N];

static void qs_swap(int *a, int *b) { int t = *a; *a = *b; *b = t; }

static int qs_partition(int lo, int hi)
{
    int pivot = qs_arr[hi];
    int i = lo - 1;
    for (int j = lo; j < hi; j++) {
        if (qs_arr[j] <= pivot) {
            i++;
            qs_swap(&qs_arr[i], &qs_arr[j]);
        }
    }
    qs_swap(&qs_arr[i + 1], &qs_arr[hi]);
    return i + 1;
}

static int quick_select(int lo, int hi, int k)
{
    while (lo < hi) {
        int p = qs_partition(lo, hi);
        if (p == k)      return qs_arr[k];
        else if (k < p)  hi = p - 1;
        else             lo = p + 1;
    }
    return qs_arr[lo];
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_quick_select(void)
{
    static const int input[QS_N] = {7, 2, 1, 6, 5, 3, 4, 8};
    static const int ks[] = {0, 3, 7};

    uint32_t sum_r = 0, xor_r = 0;
    for (int t = 0; t < 3; t++) {
        for (int i = 0; i < QS_N; i++) qs_arr[i] = input[i];
        uint32_t r = (uint32_t)quick_select(0, QS_N - 1, ks[t]);
        sum_r += r;
        xor_r ^= r;
    }
    /* sum=1+4+8=13, xor=1^4^8=13 */
    g_result = ((uint32_t)QS_N << 16) | (sum_r << 8) | (xor_r & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_quick_select();
    for (;;);
}
