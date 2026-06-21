/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Counting Paths in a DAG (memoized DP) fixture.
 *
 * Count all paths from source to destination in a Directed Acyclic Graph (DAG)
 * using top-down memoized recursion: memo[u] = number of paths from u to dst.
 *
 * Distinctive decompiler idioms:
 *   1. `if (u == dst) return 1` — base case identity
 *   2. `if (memo[u] >= 0) return memo[u]` — cache hit check
 *   3. `total += count_paths(v, dst)` — accumulate over out-edges
 *   4. `memo[u] = total; return total` — store before returning (memoize)
 *
 * DAG: 6 nodes (0..5)
 *   Edges: 0→1, 0→2, 1→3, 2→3, 3→4, 3→5, 4→5
 *
 * Path counts from each node to node 5:
 *   paths(5,5) = 1
 *   paths(4,5) = 1   (4→5)
 *   paths(3,5) = 2   (3→4→5, 3→5)
 *   paths(2,5) = 2   (2→3→4→5, 2→3→5)
 *   paths(1,5) = 2   (1→3→4→5, 1→3→5)
 *   paths(0,5) = 4   (0→1→3→4→5, 0→1→3→5, 0→2→3→4→5, 0→2→3→5)
 *
 * n          = 6
 * paths_0_5  = 4
 * xor_all    = 4^2^2^2^1^1 = 6
 *
 * g_result = (n << 16) | (paths_0_5 << 8) | xor_all = 0x00060406
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph ───────────────────────────────────────────────────────────────── */

#define CP_N  6
#define CP_NE 7

static const int cp_edges[CP_NE][2] = {
    {0,1}, {0,2}, {1,3}, {2,3}, {3,4}, {3,5}, {4,5}
};

static int cp_adj[CP_N][3];
static int cp_outdeg[CP_N];
static int cp_memo[CP_N];

/* ── Memoized path count ─────────────────────────────────────────────────── */

static int count_paths(int u, int dst)
{
    if (u == dst) return 1;
    if (cp_memo[u] >= 0) return cp_memo[u];
    int total = 0;
    for (int i = 0; i < cp_outdeg[u]; i++)
        total += count_paths(cp_adj[u][i], dst);
    cp_memo[u] = total;
    return total;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_count_paths_dag(void)
{
    /* build adjacency */
    for (int i = 0; i < CP_N; i++) { cp_outdeg[i] = 0; cp_memo[i] = -1; }
    for (int i = 0; i < CP_NE; i++) {
        int u = cp_edges[i][0], v = cp_edges[i][1];
        cp_adj[u][cp_outdeg[u]++] = v;
    }

    /* count paths from every node to node 5, accumulate xor */
    uint32_t xor_all = 0;
    for (int i = 0; i < CP_N; i++) {
        /* reset memo (memoize can carry over from previous src in this
           fixed DAG: all memos from node i's sub-DAG are still valid since
           the graph has no back edges, so we can reuse them across calls) */
        xor_all ^= (uint32_t)count_paths(i, CP_N - 1);
    }

    uint32_t paths_0_5 = (uint32_t)cp_memo[0]; /* stored by first call */
    /* paths_0_5=4, xor_all=6 */

    g_result = ((uint32_t)CP_N << 16) | (paths_0_5 << 8) | (xor_all & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_count_paths_dag();
    for (;;);
}
