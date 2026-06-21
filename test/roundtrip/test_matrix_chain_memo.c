/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Matrix Chain Multiplication (memoized) fixture.
 *
 * Finds the minimum number of scalar multiplications needed to multiply a
 * chain of matrices A1*A2*...*An using memoized divide-and-conquer.
 *
 * Recurrence:
 *   m[i][j] = 0                                   if i == j
 *   m[i][j] = min over k in [i..j-1]:
 *               m[i][k] + m[k+1][j] + p[i]*p[k+1]*p[j+1]
 *
 * Distinctive decompiler idioms:
 *   1. `if (mc_memo[i][j] >= 0) return mc_memo[i][j]` — memoization check
 *   2. `for (int k = i; k < j; k++) { cost = ... if (cost < best) best=cost; }`
 *   3. `p[i] * p[k+1] * p[j+1]` — dimension product for split cost
 *   4. Return value stored in `mc_memo[i][j] = best`
 *
 * Matrix dimensions (n=4 matrices, p has n+1=5 entries):
 *   p = {10, 30, 5, 60, 4}  → matrices 10×30, 30×5, 5×60, 60×4
 *
 * Optimal parenthesisation and cost:
 *   m[0][0..3]:
 *   m[0][1] = 10*30*5 = 1500
 *   m[1][2] = 30*5*60 = 9000
 *   m[2][3] = 5*60*4  = 1200
 *   m[0][2] = min(m[0][0]+m[1][2]+10*30*60=18000, m[0][1]+m[2][2]+10*5*60=4500) = 4500
 *   m[1][3] = min(m[1][1]+m[2][3]+30*5*4=1800, m[1][2]+m[3][3]+30*60*4=16200) = 1800
 *   Wait: m[0][2] = min:
 *     k=0: m[0][0]+m[1][2]+p[0]*p[1]*p[3] = 0+9000+10*30*60 = 9000+18000=27000
 *     k=1: m[0][1]+m[2][2]+p[0]*p[2]*p[3] = 1500+0+10*5*60 = 1500+3000=4500
 *   m[0][2] = 4500
 *   m[1][3] = min:
 *     k=1: m[1][1]+m[2][3]+p[1]*p[2]*p[4] = 0+1200+30*5*4 = 1200+600=1800
 *     k=2: m[1][2]+m[3][3]+p[1]*p[3]*p[4] = 9000+0+30*60*4 = 9000+7200=16200
 *   m[1][3] = 1800
 *   m[0][3] = min:
 *     k=0: m[0][0]+m[1][3]+p[0]*p[1]*p[4] = 0+1800+10*30*4=1800+1200=3000
 *     k=1: m[0][1]+m[2][3]+p[0]*p[2]*p[4] = 1500+1200+10*5*4=2700+200=2900
 *     k=2: m[0][2]+m[3][3]+p[0]*p[3]*p[4] = 4500+0+10*60*4=4500+2400=6900
 *   m[0][3] = 2900
 *
 * n_matrices = 4
 * optimal_cost = 2900 → too large for 1 byte. Use (2900 >> 4) = 181 = 0xB5? 181 fits.
 * Actually 2900 >> 4 = 181. Hmm but 181 > 128 and < 256 so it fits in uint8.
 * Or encode: (cost / 100) = 29 = 0x1D.
 *
 * Let me use: n=4, metric_a = cost/100 = 29, metric_b = optimal_k = 1
 *   (optimal first split is at k=1 since m[0][3] is minimized at k=1)
 *
 * g_result = (n << 16) | ((cost/100) << 8) | optimal_k = 0x04 1D 01
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MCM_N  4   /* number of matrices */

static int mc_memo[MCM_N][MCM_N];
static int mc_split[MCM_N][MCM_N];  /* best split point */
static int mc_p[MCM_N + 1];
static int mc_initialised;

static int mc_solve(int i, int j)
{
    if (i == j) return 0;
    if (mc_memo[i][j] >= 0) return mc_memo[i][j];

    int best = 0x7fffffff, best_k = i;
    for (int k = i; k < j; k++) {
        int cost = mc_solve(i, k)
                 + mc_solve(k + 1, j)
                 + mc_p[i] * mc_p[k + 1] * mc_p[j + 1];
        if (cost < best) { best = cost; best_k = k; }
    }
    mc_split[i][j] = best_k;
    return (mc_memo[i][j] = best);
}

void test_matrix_chain_memo(void)
{
    static const int p[MCM_N + 1] = {10, 30, 5, 60, 4};

    /* Initialise memo to -1 */
    for (int i = 0; i < MCM_N; i++)
        for (int j = 0; j < MCM_N; j++) {
            mc_memo[i][j] = -1;
            mc_split[i][j] = i;
        }
    for (int k = 0; k <= MCM_N; k++) mc_p[k] = p[k];

    int cost = mc_solve(0, MCM_N - 1);     /* 2900 */
    int best_k = mc_split[0][MCM_N - 1];  /* 1 */

    g_result = ((uint32_t)MCM_N        << 16)
             | ((uint32_t)(cost / 100) << 8)
             | ((uint32_t)best_k & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_matrix_chain_memo();
    for (;;);
}
