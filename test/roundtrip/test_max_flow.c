/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Maximum Flow (Dinic's algorithm) fixture.
 *
 * Dinic's algorithm: BFS to build a level graph, then DFS blocking flows.
 * Edges stored as parallel arrays with index-XOR for reverse edges
 * (forward edge 2k ↔ reverse edge 2k+1).
 *
 * Distinctive decompiler idioms:
 *   1. BFS level-graph construction with level[v] = level[u]+1 guard
 *   2. DFS with advancing iterator (iter[u]) to avoid revisiting dead ends
 *   3. cap[i^1] += f  — XOR index trick for reverse edge update
 *   4. Outer while loop: BFS then drain blocking flows until no path
 *
 * Graph (6 nodes S=0, T=5, 8 directed edges):
 *   0→1 cap=10,  0→2 cap= 8
 *   1→3 cap= 5,  1→4 cap= 7
 *   2→3 cap= 8,  2→4 cap= 3
 *   3→5 cap= 9,  4→5 cap= 6
 *
 * Min-cut: {0,1,2,3,4} vs {5} → capacity 3→5(9) + 4→5(6) = 15
 * Max flow = 15
 *
 * n_tests  = 1
 * max_flow = 15 = 0x0F
 * n_nodes  = 6
 *
 * g_result = (n_tests << 16) | (max_flow << 8) | n_nodes = 0x00010F06
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Dinic's max-flow ─────────────────────────────────────────────────────── */

#define MF_NODES  6
#define MF_EDGES  16   /* 8 directed edges × 2 (forward + reverse) */

static int mf_to[MF_EDGES];
static int mf_cap[MF_EDGES];
static int mf_nxt[MF_EDGES];   /* linked-list next for adjacency */
static int mf_head[MF_NODES];  /* head of adjacency list per node */
static int mf_ne;               /* edge counter */

static int mf_level[MF_NODES];
static int mf_iter[MF_NODES];  /* current iterator per BFS phase */

static void mf_init(void)
{
    mf_ne = 0;
    for (int i = 0; i < MF_NODES; i++) mf_head[i] = -1;
}

static void mf_add(int u, int v, int c)
{
    mf_to[mf_ne]  = v; mf_cap[mf_ne]  = c; mf_nxt[mf_ne]  = mf_head[u]; mf_head[u] = mf_ne++;
    mf_to[mf_ne]  = u; mf_cap[mf_ne]  = 0; mf_nxt[mf_ne]  = mf_head[v]; mf_head[v] = mf_ne++;
}

/* BFS: build level graph. Returns 1 if sink T is reachable. */
static int mf_bfs(int s, int t)
{
    static int q[MF_NODES];
    for (int i = 0; i < MF_NODES; i++) mf_level[i] = -1;
    mf_level[s] = 0;
    int front = 0, back = 0;
    q[back++] = s;
    while (front < back) {
        int u = q[front++];
        for (int i = mf_head[u]; i >= 0; i = mf_nxt[i]) {
            int v = mf_to[i];
            if (mf_cap[i] > 0 && mf_level[v] < 0) {
                mf_level[v] = mf_level[u] + 1;
                q[back++] = v;
            }
        }
    }
    return mf_level[t] >= 0;
}

/* DFS: send blocking flow along level graph. */
static int mf_dfs(int u, int t, int pushed)
{
    if (u == t) return pushed;
    while (mf_iter[u] >= 0) {
        int i = mf_iter[u];
        int v = mf_to[i];
        if (mf_cap[i] > 0 && mf_level[v] == mf_level[u] + 1) {
            int d = pushed < mf_cap[i] ? pushed : mf_cap[i];
            int f = mf_dfs(v, t, d);
            if (f > 0) {
                mf_cap[i]     -= f;
                mf_cap[i ^ 1] += f;
                return f;
            }
        }
        mf_iter[u] = mf_nxt[i];
    }
    return 0;
}

static int dinic(int s, int t)
{
    int flow = 0;
    while (mf_bfs(s, t)) {
        for (int i = 0; i < MF_NODES; i++) mf_iter[i] = mf_head[i];
        int f;
        while ((f = mf_dfs(s, t, 1000000)) > 0)
            flow += f;
    }
    return flow;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_max_flow(void)
{
    mf_init();
    /* Edges: S=0, T=5 */
    mf_add(0, 1, 10);
    mf_add(0, 2,  8);
    mf_add(1, 3,  5);
    mf_add(1, 4,  7);
    mf_add(2, 3,  8);
    mf_add(2, 4,  3);
    mf_add(3, 5,  9);
    mf_add(4, 5,  6);

    int mflow = dinic(0, 5);
    /* min-cut {0..4}|{5} = 9+6 = 15 */

    g_result = (1u << 16)
             | ((uint32_t)(mflow & 0xFF) << 8)
             | (uint32_t)MF_NODES;
}

__attribute__((noreturn)) void _start(void)
{
    test_max_flow();
    for (;;);
}
