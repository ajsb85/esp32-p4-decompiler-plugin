/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Johnson's All-Pairs Shortest Paths fixture.
 *
 * Johnson's algorithm handles graphs with negative-weight edges (but no negative
 * cycles) by:
 *   1. Adding a virtual source q connected to all vertices with weight 0.
 *   2. Running Bellman-Ford from q to compute h[v] (shortest path weights).
 *   3. Reweighting each edge (u,v,w) → w' = w + h[u] - h[v]  (all ≥ 0).
 *   4. Running Dijkstra from each vertex on the reweighted graph.
 *   5. Correcting Dijkstra distances: d[u][v] += h[v] - h[u].
 *
 * Distinctive decompiler idioms:
 *   1. Bellman-Ford relaxation: `if (h[u]+w < h[v]) h[v]=h[u]+w` over |V|-1 passes
 *   2. Edge reweighting: `rw = w + h[u] - h[v]` before each Dijkstra call
 *   3. Distance correction: `d[v] += h[v] - h[src]` after each Dijkstra
 *   4. Dijkstra with greedy `min_dist` extract + adjacency-list scan
 *   5. Nested loop: `for s in V: dijkstra_rw(s, apsp[s], h)`
 *
 * Graph (4 nodes, 5 directed edges — includes a negative edge):
 *   0→1: 2,  1→2: -1,  2→3: 3,  0→2: 5,  1→3: 6
 *
 * Bellman-Ford h[v]:  h = [0, 0, -1, 0]
 * Source 0 shortest paths (APSP row 0):
 *   d[0][1] = 2   (direct edge 0→1)
 *   d[0][2] = 1   (0→1→2: 2+(-1)=1, shorter than 0→2:5)
 *   d[0][3] = 4   (0→1→2→3: 2+(-1)+3=4, shorter than 0→1→3:8)
 *
 * n_nodes = 4  = 0x04
 * d[0][3] = 4  = 0x04   — would clash with n_nodes, so swap encoding:
 * Encode: d[0][3], d[0][1], d[0][2]
 *   d[0][3]=4, d[0][1]=2, d[0][2]=1 → (4<<16)|(2<<8)|1 = 0x040201
 *
 * g_result = 0x040201  (bytes 4,2,1 distinct ✓)
 */
#include <stdint.h>

volatile uint32_t g_result;

#define JN    4
#define JE    5
#define JN_INF 0x7fffffff

struct JEdge { int u, v, w; };
static const struct JEdge jn_edges[JE] = {
    {0,1, 2}, {1,2,-1}, {2,3, 3}, {0,2, 5}, {1,3, 6}
};

static int jn_h[JN];        /* Bellman-Ford h[v] */
static int jn_apsp[JN][JN]; /* final APSP distances */

static void johnson_bellman_ford(void)
{
    for (int v = 0; v < JN; v++) jn_h[v] = 0; /* virtual source distance = 0 */
    for (int iter = 0; iter < JN; iter++) {
        for (int e = 0; e < JE; e++) {
            int u = jn_edges[e].u, v = jn_edges[e].v, w = jn_edges[e].w;
            if (jn_h[u] != JN_INF && jn_h[u] + w < jn_h[v])
                jn_h[v] = jn_h[u] + w;
        }
    }
}

static void johnson_dijkstra(int src, int d[])
{
    int vis[JN] = {0};
    for (int i = 0; i < JN; i++) d[i] = JN_INF;
    d[src] = 0;
    for (int iter = 0; iter < JN; iter++) {
        int u = -1;
        for (int i = 0; i < JN; i++)
            if (!vis[i] && (u < 0 || d[i] < d[u])) u = i;
        if (u < 0 || d[u] == JN_INF) break;
        vis[u] = 1;
        for (int e = 0; e < JE; e++) {
            if (jn_edges[e].u != u) continue;
            int v = jn_edges[e].v;
            /* reweighted edge: w' = w + h[u] - h[v] */
            int rw = jn_edges[e].w + jn_h[u] - jn_h[v];
            if (d[u] + rw < d[v]) d[v] = d[u] + rw;
        }
    }
    /* de-reweight: actual dist = dijkstra_dist + h[v] - h[src] */
    for (int v = 0; v < JN; v++)
        if (d[v] < JN_INF) d[v] += jn_h[v] - jn_h[src];
}

void test_johnson_apsp(void)
{
    johnson_bellman_ford();
    for (int s = 0; s < JN; s++)
        johnson_dijkstra(s, jn_apsp[s]);
    /* d[0][3]=4, d[0][1]=2, d[0][2]=1 */
    g_result = ((uint32_t)jn_apsp[0][3] << 16)
             | ((uint32_t)jn_apsp[0][1] <<  8)
             | ((uint32_t)jn_apsp[0][2] & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_johnson_apsp();
    for (;;);
}
