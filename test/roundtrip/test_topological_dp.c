/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Topological-order DP (longest path in DAG) fixture.
 *
 * DP on a DAG in topological order is the canonical technique for:
 *   - Longest/shortest path in a weighted DAG
 *   - Counting paths
 *   - Scheduling / critical-path analysis
 *
 * Algorithm:
 *   1. Kahn's BFS-based topological sort (in-degree array, queue).
 *   2. Relax edges in topological order: dist[v] = max(dist[v], dist[u]+w).
 *   3. Longest path = max over all nodes of dist[node].
 *
 * Graph (6 nodes, 8 directed weighted edges):
 *   0→1 w=3,  0→2 w=2,
 *   1→3 w=4,  1→4 w=1,
 *   2→3 w=1,  2→4 w=5,
 *   3→5 w=2,  4→5 w=3
 *
 * Topological order: 0,1,2,3,4,5  (or 0,2,1,3,4,5 etc.)
 * dist[0]=0, dist[1]=3, dist[2]=2, dist[3]=7(0→1→3=7), dist[4]=7(0→2→4=7),
 * dist[5]=9 (max(7+2, 7+3)=10... let me recompute:
 *   dist[3] = max(dist[1]+4, dist[2]+1) = max(7,3) = 7
 *   dist[4] = max(dist[1]+1, dist[2]+5) = max(4,7) = 7
 *   dist[5] = max(dist[3]+2, dist[4]+3) = max(9,10) = 10
 * Longest path = 10 (0→2→4→5).
 * n_edges_relaxed = 8 (one relaxation per directed edge).
 *
 * Distinctive decompiler idioms:
 *   1. Kahn's topological sort: `if (--indeg[v] == 0) enqueue(v)`
 *   2. `if (dist[u] + w > dist[v]) dist[v] = dist[u] + w` (relaxation)
 *   3. Circular queue via modular index
 *   4. Final linear scan for maximum distance
 *
 * g_result = (n_nodes<<16)|(longest_path<<8)|n_edges = 0x00060A08
 *   n_nodes=6, longest_path=10=0x0A, n_edges=8
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TD_V   6   /* vertices */
#define TD_E   8   /* directed edges */

typedef struct { int u, v, w; } TDEdge;

static const TDEdge td_edges[TD_E] = {
    {0,1,3}, {0,2,2},
    {1,3,4}, {1,4,1},
    {2,3,1}, {2,4,5},
    {3,5,2}, {4,5,3},
};

static int td_indeg[TD_V];
static int td_dist[TD_V];
static int td_queue[TD_V];

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_topological_dp(void)
{
    /* Compute in-degrees */
    for (int i = 0; i < TD_E; i++)
        td_indeg[td_edges[i].v]++;

    /* Kahn's BFS topological sort + DP relaxation */
    int head = 0, tail = 0;
    for (int i = 0; i < TD_V; i++)
        if (td_indeg[i] == 0) td_queue[tail++] = i;

    int topo_cnt = 0;
    while (head < tail) {
        int u = td_queue[head++];
        topo_cnt++;
        /* Relax all outgoing edges from u */
        for (int i = 0; i < TD_E; i++) {
            if (td_edges[i].u != u) continue;
            int v = td_edges[i].v;
            int w = td_edges[i].w;
            if (td_dist[u] + w > td_dist[v])
                td_dist[v] = td_dist[u] + w;
            if (--td_indeg[v] == 0)
                td_queue[tail++] = v;
        }
    }

    /* Find longest path */
    int longest = 0;
    for (int i = 0; i < TD_V; i++)
        if (td_dist[i] > longest) longest = td_dist[i];

    /* longest=10=0x0A, TD_E=8 → g_result = 0x00060A08 */
    g_result = ((uint32_t)TD_V << 16)
             | ((uint32_t)longest << 8)
             | (uint32_t)TD_E;
}

__attribute__((noreturn)) void _start(void)
{
    test_topological_dp();
    for (;;);
}
