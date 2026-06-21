/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Knuth's Optimal BST (DP with Quadrangle Inequality).
 *
 * The optimal BST problem finds a binary search tree that minimizes the expected
 * search cost given key frequencies.  The DP recurrence is:
 *   dp[i][j] = min over k in [i..j] of (dp[i][k-1] + dp[k+1][j] + w[i][j])
 * where w[i][j] = sum of frequencies from i to j.  Knuth's observation is that
 * the optimal root satisfies root[i][j-1] <= root[i][j] <= root[i+1][j], reducing
 * the DP from O(n³) to O(n²).
 *
 * Distinctive decompiler idioms:
 *   1. `for (k = ob_root[i][j-1]; k <= ob_root[i+1][j]; k++)` — Knuth's bound
 *   2. `ob_w[i][j] = ob_w[i][j-1] + ob_freq[j]` — cumulative frequency prefix
 *   3. `cost = left + right + ob_w[i][j]` — adding root's subtree cost as weight
 *   4. 2D table fill by length: `for (l=2; l<=N; l++) for (i=0; i<=N-l; i++)`
 *   5. `ob_root[i][j] = k` — recording optimal split for traceback
 *
 * Keys: n=4 with frequencies {1, 2, 3, 4} (key 3 most frequent → prefer near root)
 * dp[0][3] = 18 (optimal cost), root[0][3] = 2 (key 2 at root)
 *   Structure: key2 at root, key3 right child, key1 left of key2, key0 leaf
 *
 * OB_N      = 4   = 0x04
 * opt_cost  = 18  = 0x12
 * opt_root  = 2   = 0x02
 *
 * g_result = (OB_N << 16) | (opt_cost << 8) | opt_root = 0x041202 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define OB_N   4
#define OB_INF 0x7fffffff

static const int ob_freq[OB_N] = {1, 2, 3, 4};

static int ob_dp[OB_N][OB_N];
static int ob_root[OB_N][OB_N];
static int ob_w[OB_N][OB_N];  /* ob_w[i][j] = sum freq[i..j] */

void test_optimal_bst(void)
{
    /* Base case: single keys */
    for (int i = 0; i < OB_N; i++) {
        ob_dp[i][i]   = ob_freq[i];
        ob_w[i][i]    = ob_freq[i];
        ob_root[i][i] = i;
    }

    /* Fill by increasing length */
    for (int l = 2; l <= OB_N; l++) {
        for (int i = 0; i <= OB_N - l; i++) {
            int j = i + l - 1;
            ob_w[i][j]  = ob_w[i][j-1] + ob_freq[j];
            ob_dp[i][j] = OB_INF;

            /* Knuth's optimization: root in [root[i][j-1], root[i+1][j]] */
            int klo = (l == 2) ? i : ob_root[i][j-1];
            int khi = (l == 2) ? j : ob_root[i+1][j];

            for (int k = klo; k <= khi; k++) {
                int left  = (k > i) ? ob_dp[i][k-1] : 0;
                int right = (k < j) ? ob_dp[k+1][j] : 0;
                int cost  = left + right + ob_w[i][j];
                if (cost < ob_dp[i][j]) {
                    ob_dp[i][j]   = cost;
                    ob_root[i][j] = k;
                }
            }
        }
    }
    /* opt_cost=18, opt_root=2 */

    g_result = ((uint32_t)OB_N                  << 16)
             | ((uint32_t)ob_dp[0][OB_N-1]      <<  8)
             | ((uint32_t)ob_root[0][OB_N-1] & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_optimal_bst();
    for (;;);
}
