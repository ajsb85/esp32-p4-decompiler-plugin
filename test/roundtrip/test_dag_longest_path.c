/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Path in a DAG fixture.
 *
 * Compute the longest path from any node to any node in a directed acyclic
 * graph (DAG) using dynamic programming in topological order.
 *
 * Distinctive decompiler idioms:
 *   1. `dp[0]=0; dp[1..n-1]=0` — init (all-zero, process in topo order)
 *   2. `for each edge (u,v,w): if(dp[u]+w > dp[v]) dp[v]=dp[u]+w` — relax
 *   3. `max_d = max over i of dp[i]` — global maximum
 *   4. `xor_dp ^= (uint32_t)dp[i]` — XOR accumulation for verification
 *
 * DAG (6 nodes, 8 directed weighted edges, already in topological order):
 *   0→1(3), 0→2(6), 1→2(4), 1→4(11), 2→3(5), 2→5(2), 3→4(1), 4→5(3)
 *
 * Longest-path DP (starting from node 0 with dp[0]=0):
 *   dp[1] = dp[0]+3 = 3
 *   dp[2] = max(dp[0]+6, dp[1]+4) = max(6,7) = 7
 *   dp[3] = dp[2]+5 = 12
 *   dp[4] = max(dp[1]+11, dp[3]+1) = max(14,13) = 14
 *   dp[5] = max(dp[2]+2, dp[4]+3) = max(9,17) = 17
 *
 * n        = 6
 * max_dist = 17
 * xor_dp   = 0^3^7^12^14^17 = 23
 *
 * g_result = (n<<16) | (max_dist<<8) | xor_dp = 0x00061117
 */
#include <stdint.h>

volatile uint32_t g_result;

#define DLP_N  6
#define DLP_NE 8

static const int dlp_eu[DLP_NE] = {0,0,1,1,2,2,3,4};
static const int dlp_ev[DLP_NE] = {1,2,2,4,3,5,4,5};
static const int dlp_ew[DLP_NE] = {3,6,4,11,5,2,1,3};

void test_dag_longest_path(void)
{
    int dp[DLP_N];
    for (int i = 0; i < DLP_N; i++) dp[i] = 0;

    for (int e = 0; e < DLP_NE; e++) {
        int u = dlp_eu[e], v = dlp_ev[e], w = dlp_ew[e];
        if (dp[u] + w > dp[v]) dp[v] = dp[u] + w;
    }

    uint32_t max_d = 0, xor_dp = 0;
    for (int i = 0; i < DLP_N; i++) {
        if ((uint32_t)dp[i] > max_d) max_d = (uint32_t)dp[i];
        xor_dp ^= (uint32_t)dp[i];
    }
    /* max_d=17, xor_dp=23 */
    g_result = ((uint32_t)DLP_N << 16) | ((max_d & 0xFFu) << 8) | (xor_dp & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_dag_longest_path();
    for (;;);
}
