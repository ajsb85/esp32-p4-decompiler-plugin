/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Minimum Path Sum (Grid DP).
 *
 * Finds minimum cost path from top-left to bottom-right in a grid.
 * Only right and down moves allowed.
 * dp[i][j] = min(dp[i-1][j], dp[i][j-1]) + grid[i][j]
 *
 * Distinctive decompiler idioms:
 *   1. `dp[i][0]=dp[i-1][0]+grid[i][0]` — left column: only down
 *   2. `dp[0][j]=dp[0][j-1]+grid[0][j]` — top row: only right
 *   3. `dp[i][j]=(a<b?a:b)+grid[i][j]` — min of up/left neighbors
 *
 * Grid 1 (3×3): min path = 1+3+1+1+1=7
 * Grid 2 (3×4): min path = 1+2+1+2+1+3 → computed = 9
 *
 * g_result = (2<<16)|(p1<<8)|p2 = 0x00020709
 */
#include <stdint.h>

volatile uint32_t g_result;

static int dp_mps[3][5];

void test_min_path_sum(void)
{
    static const int m1[3][3] = {{1,3,1},{1,5,1},{4,2,1}};
    static const int m2[3][4] = {{1,2,5,3},{1,1,2,1},{4,2,1,3}};
    int i, j;

    /* Grid 1: 3×3 */
    dp_mps[0][0] = m1[0][0];
    for (j = 1; j < 3; j++) dp_mps[0][j] = dp_mps[0][j-1] + m1[0][j];
    for (i = 1; i < 3; i++) dp_mps[i][0] = dp_mps[i-1][0] + m1[i][0];
    for (i = 1; i < 3; i++)
        for (j = 1; j < 3; j++) {
            int a = dp_mps[i-1][j], b = dp_mps[i][j-1];
            dp_mps[i][j] = (a < b ? a : b) + m1[i][j];
        }
    int p1 = dp_mps[2][2];

    /* Grid 2: 3×4 */
    dp_mps[0][0] = m2[0][0];
    for (j = 1; j < 4; j++) dp_mps[0][j] = dp_mps[0][j-1] + m2[0][j];
    for (i = 1; i < 3; i++) dp_mps[i][0] = dp_mps[i-1][0] + m2[i][0];
    for (i = 1; i < 3; i++)
        for (j = 1; j < 4; j++) {
            int a = dp_mps[i-1][j], b = dp_mps[i][j-1];
            dp_mps[i][j] = (a < b ? a : b) + m2[i][j];
        }
    int p2 = dp_mps[2][3];

    /* p1=7, p2=9 */
    g_result = (2u << 16)
             | ((uint32_t)p1 << 8)
             | (uint32_t)p2;
}

__attribute__((noreturn)) void _start(void)
{
    test_min_path_sum();
    for (;;);
}
