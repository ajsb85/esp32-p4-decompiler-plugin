/* test_monotone_minima.c
 * Monotone-minima algorithm: for an n×m totally monotone matrix, find the
 * column index of the row minimum for every row in O(n + m log n) time.
 * Used as an inner step in SMAWK and various DP optimizations.
 * All 32-bit arithmetic.
 */
#include <stdint.h>

#define MM_ROWS 8u
#define MM_COLS 8u

volatile uint32_t g_result;

/* A totally monotone cost matrix (col of min is non-decreasing row by row).
 * Entry (i,j) = (i+1)*(j+1) + |i-j|*3 — satisfies the monotone property. */
static uint32_t mm_cost(uint32_t i, uint32_t j) {
    uint32_t diff = (i >= j) ? (i - j) : (j - i);
    return (i + 1u) * (j + 1u) + diff * 3u;
}

/* row-minimum column indices */
static uint32_t mm_argmin[MM_ROWS];

/* Divide-and-conquer monotone minima.
 * rows[rs..re) considered, col range [cs..ce). */
static void mm_dc(uint32_t rs, uint32_t re, uint32_t cs, uint32_t ce) {
    if (rs >= re) return;
    uint32_t mid_r = rs + (re - rs) / 2u;
    uint32_t best_col = cs;
    uint32_t best_val = mm_cost(mid_r, cs);
    for (uint32_t c = cs + 1u; c < ce; c++) {
        uint32_t v = mm_cost(mid_r, c);
        if (v < best_val) {
            best_val = v;
            best_col = c;
        }
    }
    mm_argmin[mid_r] = best_col;
    /* recurse: upper half restricted to [cs .. best_col+1) */
    if (mid_r > rs) {
        uint32_t right_bound = best_col + 1u;
        if (right_bound > ce) right_bound = ce;
        mm_dc(rs, mid_r, cs, right_bound);
    }
    /* lower half restricted to [best_col .. ce) */
    if (mid_r + 1u < re) {
        mm_dc(mid_r + 1u, re, best_col, ce);
    }
}

void _start(void) {
    mm_dc(0u, MM_ROWS, 0u, MM_COLS);

    /* verify monotone property: argmin must be non-decreasing */
    uint32_t monotone_ok = 1u;
    for (uint32_t i = 1u; i < MM_ROWS; i++) {
        if (mm_argmin[i] < mm_argmin[i - 1u]) {
            monotone_ok = 0u;
        }
    }

    uint32_t sum_argmin = 0u;
    for (uint32_t i = 0u; i < MM_ROWS; i++) {
        sum_argmin += mm_argmin[i];
    }

    uint32_t n_tests  = 3u;
    uint32_t metric_a = (uint32_t)((sum_argmin & 0x7Fu) | 0x01u);
    uint32_t metric_b = (uint32_t)((monotone_ok << 4) | (mm_argmin[MM_ROWS - 1u] + 1u));
    if (metric_b == 0u) metric_b = 0x11u;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    while (1) {}
}
