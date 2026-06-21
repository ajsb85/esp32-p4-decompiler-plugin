/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Kosaraju's SCC (Strongly Connected Components) fixture.
 *
 * Kosaraju's two-pass DFS algorithm for SCCs:
 *   Pass 1: DFS on original graph; push nodes to stack in finish order.
 *   Pass 2: DFS on transposed graph in reverse finish order; each DFS tree
 *           is one SCC.
 *
 * Distinctive decompiler idioms:
 *   1. Recursive DFS with visited array: `if (!visited[v]) dfs1(v);`
 *   2. Post-order push: `stk[stk_top++] = u;` after all neighbours explored
 *   3. Transposed adjacency matrix: `gt[v][u] = 1` for original edge `u→v`
 *   4. Reverse-stack iteration: `u = stk[--stk_top];` in second pass
 *
 * Graph (6 nodes, 7 directed edges):
 *   SCC-A: {0,1,2}  edges 0→1, 1→2, 2→0
 *   SCC-B: {3,4,5}  edges 3→4, 4→5, 5→3
 *   Cross edge: 0→3 (not reciprocated)
 *
 * Expected:
 *   n_sccs    = 2
 *   max_size  = 3   (both SCCs have 3 nodes)
 *   n_nodes   = 6
 *
 * g_result = (n_nodes << 16) | (n_sccs << 8) | max_size = 0x00060203
 */
#include <stdint.h>

volatile uint32_t g_result;

#define KOS_N 6

/* Original and transposed adjacency matrices */
static int g[KOS_N][KOS_N];
static int gt[KOS_N][KOS_N];

static int visited[KOS_N];
static int stk[KOS_N];
static int stk_top;

static int scc_count;
static int scc_sizes[KOS_N];

/* ── Pass 1: DFS in original graph, push in finish order ─────────────────── */

static void dfs1(int u)
{
    visited[u] = 1;
    for (int v = 0; v < KOS_N; v++)
        if (g[u][v] && !visited[v])
            dfs1(v);
    stk[stk_top++] = u;
}

/* ── Pass 2: DFS in transposed graph, label SCC ──────────────────────────── */

static void dfs2(int u, int id)
{
    visited[u] = 1;
    scc_sizes[id]++;
    for (int v = 0; v < KOS_N; v++)
        if (gt[u][v] && !visited[v])
            dfs2(v, id);
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_kosaraju(void)
{
    /* Build original graph edges */
    g[0][1] = g[1][2] = g[2][0] = 1;  /* SCC-A cycle */
    g[3][4] = g[4][5] = g[5][3] = 1;  /* SCC-B cycle */
    g[0][3] = 1;                        /* cross edge  */

    /* Build transposed graph */
    for (int u = 0; u < KOS_N; u++)
        for (int v = 0; v < KOS_N; v++)
            if (g[u][v]) gt[v][u] = 1;

    /* Pass 1: compute finish order */
    for (int u = 0; u < KOS_N; u++)
        if (!visited[u]) dfs1(u);

    /* Pass 2: mark SCCs in reverse finish order */
    for (int i = 0; i < KOS_N; i++) visited[i] = 0;
    scc_count = 0;
    while (stk_top > 0) {
        int u = stk[--stk_top];
        if (!visited[u]) {
            dfs2(u, scc_count);
            scc_count++;
        }
    }

    /* Find max SCC size */
    int max_sz = 0;
    for (int i = 0; i < scc_count; i++)
        if (scc_sizes[i] > max_sz) max_sz = scc_sizes[i];

    /* n_sccs=2, max_sz=3, n_nodes=6 */
    g_result = ((uint32_t)KOS_N << 16)
             | ((uint32_t)scc_count << 8)
             | (uint32_t)max_sz;
}

__attribute__((noreturn)) void _start(void)
{
    test_kosaraju();
    for (;;);
}
