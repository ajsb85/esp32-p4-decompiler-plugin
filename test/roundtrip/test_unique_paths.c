/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Unique Paths in Grid (2-D DP) fixture.
 *
 * Count distinct paths from top-left to bottom-right in an m×n grid,
 * moving only right or down.
 *
 * Recurrence: dp[i][j] = dp[i-1][j] + dp[i][j-1]
 * Base cases:  dp[0][j] = 1  (top row: only one way — all right)
 *              dp[i][0] = 1  (left col: only one way — all down)
 *
 * Distinctive decompiler idioms:
 *   1. `dp[i][j] = (i==0||j==0) ? 1 : dp[i-1][j] + dp[i][j-1]` — combined init+fill
 *   2. Double loop `for i: for j:` over rectangular grid
 *   3. Answer is dp[m-1][n-1]
 *
 * Test grids:
 *   3×3  → 6   (C(4,2))
 *   3×7  → 28  (C(8,2))
 *   4×4  → 20  (C(6,3))
 *
 * n_tests    = 3
 * sum_paths  = 6+28+20 = 54  (0x36)
 * xor_paths  = 6^28^20       = 14  (0x0E)
 *
 * g_result = (3 << 16) | (54 << 8) | 14 = 0x0003360E
 */
#include <stdint.h>

volatile uint32_t g_result;

#define UP_MAXM 4
#define UP_MAXN 8

static int up_dp[UP_MAXM][UP_MAXN];

static int unique_paths(int m, int n)
{
    for (int i = 0; i < m; i++)
        for (int j = 0; j < n; j++)
            up_dp[i][j] = (i == 0 || j == 0) ? 1
                                              : up_dp[i-1][j] + up_dp[i][j-1];
    return up_dp[m-1][n-1];
}

void test_unique_paths(void)
{
    int r1 = unique_paths(3, 3); /*  6 */
    int r2 = unique_paths(3, 7); /* 28 */
    int r3 = unique_paths(4, 4); /* 20 */

    uint32_t sum_p = (uint32_t)(r1 + r2 + r3); /* 54 */
    uint32_t xor_p = (uint32_t)(r1 ^ r2 ^ r3); /* 14 */

    g_result = (3u << 16) | ((sum_p & 0xFFu) << 8) | (xor_p & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_unique_paths();
    for (;;);
}
