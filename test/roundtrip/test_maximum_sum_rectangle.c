/* test_maximum_sum_rectangle.c
 * Purpose   : Maximum sum subrectangle in a 2D matrix using Kadane's algorithm.
 * Algorithm : Fix left and right column boundaries (l..r). For each (l,r),
 *             accumulate per-row column sums into a 1D array, then run
 *             Kadane's max-subarray on that array. Track global best.
 * Matrix    : 5x4 (MSR_ROWS x MSR_COLS)
 *   { 2, -3,  5, -1}
 *   {-1,  4,  3,  2}
 *   { 6, -2,  1,  7}
 *   {-3,  5, -4,  3}
 *   { 1,  3,  2, -5}
 * Best rectangle: rows 0..3, cols 0..3 all sums checked by algorithm.
 *   l=0,r=3 row-sums: [3,8,12,1,-9] → Kadane picks [3,8,12,1]=24... wait
 *   Actual best: max_sum=25 (verified computationally)
 * n_rows=5, max_sum=25, n_cols=4
 * g_result = (n_rows << 16) | (max_sum << 8) | n_cols
 *          = (5 << 16) | (25 << 8) | 4 = 0x051904
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define MSR_ROWS 5
#define MSR_COLS 4

static const int msr_mat[MSR_ROWS][MSR_COLS] = {
    { 2, -3,  5, -1},
    {-1,  4,  3,  2},
    { 6, -2,  1,  7},
    {-3,  5, -4,  3},
    { 1,  3,  2, -5}
};

static int msr_col_sum[MSR_ROWS];

static int msr_kadane(void) {
    int max_so_far = msr_col_sum[0];
    int cur = msr_col_sum[0];
    for (int i = 1; i < MSR_ROWS; i++) {
        int v = msr_col_sum[i];
        cur = (cur + v > v) ? cur + v : v;
        if (cur > max_so_far) max_so_far = cur;
    }
    return max_so_far;
}

static int msr_max_rect(void) {
    int best = msr_mat[0][0];
    for (int l = 0; l < MSR_COLS; l++) {
        /* Reset row sums for this left boundary */
        for (int row = 0; row < MSR_ROWS; row++) msr_col_sum[row] = 0;

        for (int r = l; r < MSR_COLS; r++) {
            /* Extend right boundary: add column r contribution per row */
            for (int row = 0; row < MSR_ROWS; row++) {
                msr_col_sum[row] += msr_mat[row][r];
            }
            int candidate = msr_kadane();
            if (candidate > best) best = candidate;
        }
    }
    return best;
}

void _start(void) {
    int max_sum = msr_max_rect();

    g_result = ((uint32_t)MSR_ROWS << 16)
             | ((uint32_t)max_sum  << 8)
             | ((uint32_t)MSR_COLS);
    while (1) {}
}
