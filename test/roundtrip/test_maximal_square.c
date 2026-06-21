/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Maximal Square in Binary Matrix fixture.
 *
 * Finds the side length of the largest square sub-matrix of 1s using DP:
 *   dp[i][j] = min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]) + 1  if mat[i][j]==1
 *            = 0                                                  otherwise
 * Answer = max(dp[i][j])^2 (area).
 *
 * Distinctive decompiler idioms:
 *   1. `dp[i][j] = MIN3(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]) + 1` — 3-way min
 *   2. Base case: `if (i==0 || j==0) dp[i][j] = mat[i][j]`
 *   3. `if (dp[i][j] > max_side) max_side = dp[i][j]`
 *
 * Matrix 4×5:
 *   1 0 1 0 0
 *   1 0 1 1 1
 *   1 1 1 1 1
 *   1 0 0 1 0
 * Largest square: 2×2 at rows[1..2],cols[2..3]. max_area=4.
 *
 * g_result = (n_rows<<16) | (max_area<<8) | n_cols = 0x00040405
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MS_MIN3(a,b,c) ((a)<(b)?((a)<(c)?(a):(c)):((b)<(c)?(b):(c)))

void test_maximal_square(void)
{
    static const int mat[4][5] = {
        {1,0,1,0,0},
        {1,0,1,1,1},
        {1,1,1,1,1},
        {1,0,0,1,0}
    };
    static int dp[4][5];
    int n_rows = 4, n_cols = 5;
    int max_side = 0;

    for (int i = 0; i < n_rows; i++) {
        for (int j = 0; j < n_cols; j++) {
            if (mat[i][j] == 1) {
                if (i == 0 || j == 0) {
                    dp[i][j] = 1;
                } else {
                    dp[i][j] = MS_MIN3(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]) + 1;
                }
                if (dp[i][j] > max_side) max_side = dp[i][j];
            } else {
                dp[i][j] = 0;
            }
        }
    }
    /* max_side=2, max_area=4, n_rows=4, n_cols=5 */
    g_result = ((uint32_t)n_rows << 16)
             | ((uint32_t)(max_side * max_side) << 8)
             | (uint32_t)n_cols;
}

__attribute__((noreturn)) void _start(void)
{
    test_maximal_square();
    for (;;);
}
