/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Matrix Chain Multiplication DP fixture.
 *
 * Classic O(n³) interval DP: find minimum scalar multiplications to compute
 * the product of a chain of matrices A₁A₂…Aₙ.
 *
 * Recurrence:
 *   dp[i][i] = 0
 *   dp[i][j] = min over i≤k<j of: dp[i][k] + dp[k+1][j] + dims[i]*dims[k+1]*dims[j+1]
 *
 * Distinctive decompiler idioms:
 *   1. Outer loop over chain length l = 2..n (diagonal sweep)
 *   2. dp[i][j] = INT_MAX sentinel; inner k-loop with cost formula
 *   3. if (cost < dp[i][j]) dp[i][j] = cost  ← minimize in place
 *
 * Input: dims = {2, 3, 4, 5}  → 3 matrices: (2×3)(3×4)(4×5)
 *
 * n_matrices = 3
 *
 * DP table (0-indexed: dp[i][j] = min ops to multiply matrices i..j):
 *   dp[0][0]=0, dp[1][1]=0, dp[2][2]=0
 *   l=2:
 *     dp[0][1]: k=0: 0+0+dims[0]*dims[1]*dims[2] = 2*3*4 = 24
 *     dp[1][2]: k=1: 0+0+dims[1]*dims[2]*dims[3] = 3*4*5 = 60
 *   l=3:
 *     dp[0][2]:
 *       k=0: dp[0][0]+dp[1][2]+dims[0]*dims[1]*dims[3] = 0+60+2*3*5 = 90
 *       k=1: dp[0][1]+dp[2][2]+dims[0]*dims[2]*dims[3] = 24+0+2*4*5 = 64
 *       min = 64
 *
 * g_result = (n_matrices << 16) | (dp[0][n-1] << 8) | dp[0][1]
 *          = (3 << 16) | (64 << 8) | 24
 *          = 0x00034018
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Matrix Chain DP ──────────────────────────────────────────────────────── */

#define MC_N 3

static int mc_dp[MC_N][MC_N];

static void matrix_chain(const int *dims, int n)
{
    for (int i = 0; i < n; i++) mc_dp[i][i] = 0;

    for (int l = 2; l <= n; l++) {
        for (int i = 0; i <= n - l; i++) {
            int j = i + l - 1;
            mc_dp[i][j] = 0x7fffffff;
            for (int k = i; k < j; k++) {
                int cost = mc_dp[i][k] + mc_dp[k + 1][j]
                         + dims[i] * dims[k + 1] * dims[j + 1];
                if (cost < mc_dp[i][j])
                    mc_dp[i][j] = cost;
            }
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_matrix_chain(void)
{
    static const int dims[] = {2, 3, 4, 5};

    matrix_chain(dims, MC_N);
    /* dp[0][2]=64 (min ops all 3), dp[0][1]=24 (first pair) */

    g_result = ((uint32_t)MC_N << 16)
             | ((uint32_t)mc_dp[0][MC_N - 1] << 8)
             | (uint32_t)mc_dp[0][1];
}

__attribute__((noreturn)) void _start(void)
{
    test_matrix_chain();
    for (;;);
}
