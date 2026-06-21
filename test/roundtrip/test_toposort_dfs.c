/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — DFS-based Topological Sort fixture.
 *
 * Topological sort via DFS: push each node to a stack *after* all its
 * reachable successors have been pushed. Reading the stack top-to-bottom
 * gives a valid topological order.
 *
 * Distinctive decompiler idioms:
 *   1. `visited[v] = 1` set at entry of DFS
 *   2. `for each neighbor u: if (!visited[u]) dfs(u)` — recurse first
 *   3. `stack[top++] = v` — push AFTER recursing (post-order)
 *   4. `order[j++] = stack[--top]` — reverse stack = topological order
 *
 * Graph: 5 nodes (0..4)
 *   Edges: 4→2, 4→3, 2→0, 2→1, 3→1
 *
 * DFS iteration order (0..4, first unvisited):
 *   Visit 0: no out-edges → push 0
 *   Visit 1: no out-edges → push 1
 *   Visit 2: neighbors 0,1 already visited → push 2
 *   Visit 3: neighbor 1 already visited → push 3
 *   Visit 4: neighbors 2,3 already visited → push 4
 *   Stack: [0,1,2,3,4] → topo order (reversed): [4,3,2,1,0]
 *
 * n          = 5
 * sum_order  = 4+3+2+1+0 = 10 = 0x0A
 * xor_order  = 4^3^2^1^0 = 4
 *
 * g_result = (n << 16) | (sum_order << 8) | xor_order = 0x00050A04
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph ───────────────────────────────────────────────────────────────── */

#define TD_N 5

static const int td_adj_init[TD_N][2] = {{-1,-1},{-1,-1},{0,1},{1,-1},{2,3}};
static const int td_deg_init[TD_N]    = {0, 0, 2, 1, 2};

static int td_adj[TD_N][2];
static int td_deg[TD_N];

/* ── DFS state ───────────────────────────────────────────────────────────── */

static int td_vis[TD_N];
static int td_stk[TD_N];
static int td_top;

/* ── DFS ─────────────────────────────────────────────────────────────────── */

static void td_dfs(int v)
{
    td_vis[v] = 1;
    for (int i = 0; i < td_deg[v]; i++)
        if (!td_vis[td_adj[v][i]]) td_dfs(td_adj[v][i]);
    td_stk[td_top++] = v;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_toposort_dfs(void)
{
    for (int i = 0; i < TD_N; i++) {
        td_adj[i][0] = td_adj_init[i][0];
        td_adj[i][1] = td_adj_init[i][1];
        td_deg[i]    = td_deg_init[i];
        td_vis[i]    = 0;
    }
    td_top = 0;

    for (int i = 0; i < TD_N; i++)
        if (!td_vis[i]) td_dfs(i);

    /* Reverse stack to get topological order [4,3,2,1,0] */
    uint32_t s = 0, x = 0;
    for (int i = td_top - 1; i >= 0; i--) {
        s += (uint32_t)td_stk[i];
        x ^= (uint32_t)td_stk[i];
    }

    /* sum=10, xor=4 */
    g_result = ((uint32_t)TD_N << 16) | ((s & 0xFFu) << 8) | (x & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_toposort_dfs();
    for (;;);
}
