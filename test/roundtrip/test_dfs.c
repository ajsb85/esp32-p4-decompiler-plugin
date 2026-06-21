/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Depth-First Search (DFS) round-trip fixture.
 *
 * Recursive DFS on a 6-node directed acyclic graph (DAG) stored as an
 * adjacency matrix.  Records post-order finish times for each node.
 *
 * Directed edges:
 *   0→1, 0→2, 1→3, 2→3, 3→4, 4→5
 *
 *   Topology: 0 → {1,2} → 3 → 4 → 5
 *
 * DFS trace from node 0 (neighbors explored left-to-right):
 *   Visit 0 → Visit 1 → Visit 3 → Visit 4 → Visit 5
 *     Finish 5 (f=1) ← 4 (f=2) ← 3 (f=3) ← 1 (f=4)
 *   Visit 2 → 3 already visited (cross edge)
 *     Finish 2 (f=5) ← 0 (f=6)
 *
 * Finish times: f = {6, 4, 5, 3, 2, 1}
 *   sum_finish = 6+4+5+3+2+1 = 21 = 0x15
 *   xor_finish = 6^4^5^3^2^1 = 7
 *   n_reachable = 6
 *
 * g_result = (n_reachable << 16) | (sum_finish << 8) | xor_finish
 *           = (6 << 16) | (21 << 8) | 7 = 0x00061507
 *
 * Recognizable decompiler idioms:
 *   dfs_visited[v] = 1;               ← mark visited
 *   for (u): if (adj[v][u] && !vis[u]) dfs(u);  ← recurse on neighbors
 *   dfs_finish[v] = ++timer;          ← post-order finish time
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph (directed, 6 nodes) ───────────────────────────────────────────── */

#define N 6

static const int dadj[N][N] = {
    /*     0  1  2  3  4  5 */
    /* 0 */{0, 1, 1, 0, 0, 0},
    /* 1 */{0, 0, 0, 1, 0, 0},
    /* 2 */{0, 0, 0, 1, 0, 0},
    /* 3 */{0, 0, 0, 0, 1, 0},
    /* 4 */{0, 0, 0, 0, 0, 1},
    /* 5 */{0, 0, 0, 0, 0, 0},
};

static int dfs_visited[N];
static int dfs_finish[N];
static int dfs_timer;

static void dfs(int v)
{
    dfs_visited[v] = 1;
    for (int u = 0; u < N; u++) {
        if (dadj[v][u] && !dfs_visited[u])
            dfs(u);
    }
    dfs_finish[v] = ++dfs_timer;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_dfs(void)
{
    for (int i = 0; i < N; i++) {
        dfs_visited[i] = 0;
        dfs_finish[i]  = 0;
    }
    dfs_timer = 0;
    dfs(0);

    uint32_t sum_f = 0, xor_f = 0;
    int n_reached = 0;
    for (int i = 0; i < N; i++) {
        if (dfs_visited[i]) {
            n_reached++;
            sum_f += (uint32_t)dfs_finish[i];
            xor_f ^= (uint32_t)dfs_finish[i];
        }
    }

    g_result = ((uint32_t)n_reached << 16)
             | (sum_f << 8)
             | (xor_f & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_dfs();
    for (;;);
}
