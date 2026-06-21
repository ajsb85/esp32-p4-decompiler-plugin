/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Maximum Sum Rectangle in 2D Matrix fixture.
 *
 * Find the maximum-sum sub-rectangle in a 2D matrix by fixing the left and
 * right column boundaries and applying Kadane's algorithm on the compressed
 * row sums.  O(cols² × rows) time, O(rows) extra space.
 *
 * Distinctive decompiler idioms:
 *   1. `for l=0..cols-1: for r=l..cols-1: temp[i]+=mat[i][r]` — column compress
 *   2. `kadane1d(temp, rows)` — 1-D maximum sub-array on compressed column sums
 *   3. `if(max_here+a[i]>a[i]) max_here+=a[i]; else max_here=a[i]` — Kadane update
 *   4. `if(s>max_sum) max_sum=s` — track global maximum
 *
 * Matrix (3 rows × 4 cols):
 *    1   2  -1  -4
 *   -8  -3   4   2
 *    3   8  10  -8
 *
 * Best sub-rectangle: single row 2 (cols 0-2) = 3+8+10 = 21
 * n_cells = 3×4 = 12,  max_sum = 21
 *
 * g_result = (12<<16) | (21<<8) | 1 = 0x000C1501
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MR_ROWS 3
#define MR_COLS 4

static const int mr_mat[MR_ROWS][MR_COLS] = {
    { 1,  2, -1, -4},
    {-8, -3,  4,  2},
    { 3,  8, 10, -8}
};

static int kadane1d(int *a, int n)
{
    int max_here = a[0], max_so_far = a[0];
    for (int i = 1; i < n; i++) {
        int next = max_here + a[i];
        max_here  = next > a[i] ? next : a[i];
        if (max_here > max_so_far) max_so_far = max_here;
    }
    return max_so_far;
}

void test_max_rect_sum(void)
{
    int temp[MR_ROWS];
    int max_sum = -0x7fffffff;

    for (int l = 0; l < MR_COLS; l++) {
        for (int i = 0; i < MR_ROWS; i++) temp[i] = 0;
        for (int r = l; r < MR_COLS; r++) {
            for (int i = 0; i < MR_ROWS; i++) temp[i] += mr_mat[i][r];
            int s = kadane1d(temp, MR_ROWS);
            if (s > max_sum) max_sum = s;
        }
    }
    /* max_sum = 21 (row 2, cols 0..2) */
    g_result = ((uint32_t)(MR_ROWS * MR_COLS) << 16)
             | ((uint32_t)(max_sum & 0xFF) << 8)
             | 1u;
}

__attribute__((noreturn)) void _start(void)
{
    test_max_rect_sum();
    for (;;);
}
