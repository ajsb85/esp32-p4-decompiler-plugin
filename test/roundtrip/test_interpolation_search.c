/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Interpolation Search fixture.
 *
 * Improved binary search for uniformly distributed sorted data.
 * Estimates the probe position via linear interpolation:
 *
 *   pos = lo + (key - arr[lo]) * (hi - lo) / (arr[hi] - arr[lo])
 *
 * Distinctive decompiler idiom (vs binary search):
 *   1. Non-trivial probe: multiplication + division by value range
 *   2. `(key - arr[lo]) * (hi - lo) / (arr[hi] - arr[lo])` — value-weighted
 *   3. Same lo/hi bounds as binary search but convergence is faster on uniform data
 *
 * Input (n=8, evenly spaced by 2): {1, 3, 5, 7, 9, 11, 13, 15}
 *
 * Queries: find 7, find 13
 *
 *   find 7:
 *     lo=0, hi=7
 *     pos = 0 + (7-1)*(7-0)/(15-1) = 6*7/14 = 3
 *     arr[3]=7 ✓ → idx=3
 *
 *   find 13:
 *     lo=0, hi=7
 *     pos = 0 + (13-1)*(7-0)/(15-1) = 12*7/14 = 6
 *     arr[6]=13 ✓ → idx=6
 *
 * count    = 2
 * xor_idx  = 3^6 = 5
 *
 * g_result = (n << 16) | (count << 8) | xor_idx = 0x00080205
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Interpolation Search ─────────────────────────────────────────────────── */

#define IS_N 8

static int interp_search(const int *arr, int n, int key)
{
    int lo = 0, hi = n - 1;
    while (lo <= hi && key >= arr[lo] && key <= arr[hi]) {
        if (lo == hi) return (arr[lo] == key) ? lo : -1;
        int pos = lo + (key - arr[lo]) * (hi - lo) / (arr[hi] - arr[lo]);
        if (arr[pos] == key)  return pos;
        if (arr[pos] < key)   lo = pos + 1;
        else                  hi = pos - 1;
    }
    return -1;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_interpolation_search(void)
{
    static const int arr[IS_N] = {1, 3, 5, 7, 9, 11, 13, 15};
    static const int qs[] = {7, 13};

    uint32_t count = 0, xor_idx = 0;
    for (int q = 0; q < 2; q++) {
        int idx = interp_search(arr, IS_N, qs[q]);
        if (idx >= 0) {
            count++;
            xor_idx ^= (uint32_t)idx;
        }
    }
    /* count=2, xor_idx=3^6=5 */

    g_result = ((uint32_t)IS_N << 16) | (count << 8) | (xor_idx & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_interpolation_search();
    for (;;);
}
