/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Ternary Search fixture.
 *
 * Finds the minimum of a strictly unimodal (convex) function on integer [lo,hi]
 * by partitioning the domain into thirds at each step.
 *
 * Two midpoints per iteration (vs one for binary search):
 *   m1 = lo + (hi - lo) / 3
 *   m2 = hi - (hi - lo) / 3
 *   if f(m1) <= f(m2): hi = m2 - 1   (left third survives)
 *   else:              lo = m1 + 1   (right third survives)
 *
 * Distinctive decompiler idioms vs binary search:
 *   1. Two midpoints per iteration instead of one
 *   2. `(hi - lo) / 3` offset (not `(lo + hi) / 2`)
 *   3. Outer condition: `while (hi - lo > 2)` (leave ≤3 elements for scan)
 *   4. Final linear scan of remaining [lo..hi] to find true minimum
 *
 * Function: f(x, t) = (x - t)^2  (strictly convex on integers)
 *
 * Three queries:
 *   ts_find_min(0,  7,  3) → x=3   f(3)=0
 *   ts_find_min(1,  9,  5) → x=5   f(5)=0
 *   ts_find_min(4, 12,  8) → x=8   f(8)=0
 *
 * n_queries = 3
 * sum       = 3+5+8 = 16   (0x10)
 * xor       = 3^5^8 = 14   (0x0E)
 *
 * g_result = (n_queries << 16) | (sum << 8) | xor = 0x0003100E
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Ternary Search ──────────────────────────────────────────────────────── */

#define TS_QUERIES 3

static int ts_f(int x, int t) { return (x - t) * (x - t); }

static int ts_find_min(int lo, int hi, int t)
{
    while (hi - lo > 2) {
        int m1 = lo + (hi - lo) / 3;
        int m2 = hi - (hi - lo) / 3;
        if (ts_f(m1, t) <= ts_f(m2, t)) hi = m2 - 1;
        else                             lo = m1 + 1;
    }
    int best = lo;
    for (int i = lo + 1; i <= hi; i++)
        if (ts_f(i, t) < ts_f(best, t)) best = i;
    return best;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_ternary_search(void)
{
    static const int ts_lo[TS_QUERIES]  = {0, 1, 4};
    static const int ts_hi[TS_QUERIES]  = {7, 9, 12};
    static const int ts_tgt[TS_QUERIES] = {3, 5,  8};

    uint32_t sum_m = 0, xor_m = 0;
    for (int q = 0; q < TS_QUERIES; q++) {
        int m = ts_find_min(ts_lo[q], ts_hi[q], ts_tgt[q]);
        sum_m += (uint32_t)m;
        xor_m ^= (uint32_t)m;
    }
    /* sum=16, xor=14 */

    g_result = ((uint32_t)TS_QUERIES << 16) | (sum_m << 8) | (xor_m & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_ternary_search();
    for (;;);
}
