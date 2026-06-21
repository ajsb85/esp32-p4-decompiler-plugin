/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Kruskal's MST fixture.
 *
 * Kruskal's algorithm builds an MST by processing edges in sorted order
 * and using Union-Find (path-compressed) to detect cycles:
 *
 *   sort edges by weight;
 *   for each (u,v,w): if find(u) != find(v): union(u,v); total += w; e_count++;
 *
 * Distinctive idioms (different from Prim's which works vertex-to-vertex):
 *   1. Edge-list sort by weight (insertion sort used here for bare-metal)
 *   2. Union-Find path compression: while(parent[x]!=x) x=parent[x]=parent[parent[x]]
 *   3. Union by rank: attach smaller-rank tree under larger-rank root
 *   4. MST edge count terminates at n-1
 *
 * Graph (n=5 nodes, 8 edges):
 *   (0,1,1) (1,2,2) (2,3,3) (0,2,4) (1,3,5) (3,4,6) (0,3,7) (2,4,8)
 *
 * Sorted order by weight → MST trace:
 *   (0,1,1): find(0)≠find(1) → union; weight=1,  edges=1
 *   (1,2,2): find(1)≠find(2) → union; weight=3,  edges=2
 *   (2,3,3): find(2)≠find(3) → union; weight=6,  edges=3
 *   (0,2,4): find(0)==find(2) → skip
 *   (1,3,5): find(1)==find(3) → skip
 *   (3,4,6): find(3)≠find(4) → union; weight=12, edges=4  (= n-1 → done)
 *
 * n_nodes    = 5
 * mst_weight = 12
 * mst_edges  = 4
 *
 * g_result = (n_nodes << 16) | (mst_weight << 8) | mst_edges = 0x00050C04
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Union-Find ───────────────────────────────────────────────────────────── */

#define KR_N    5
#define KR_NE   8

static int kr_parent[KR_N];
static int kr_rank[KR_N];

static void kr_init(void)
{
    for (int i = 0; i < KR_N; i++) { kr_parent[i] = i; kr_rank[i] = 0; }
}

static int kr_find(int x)
{
    while (kr_parent[x] != x)
        x = kr_parent[x] = kr_parent[kr_parent[x]];  /* path compression */
    return x;
}

static int kr_union(int a, int b)
{
    int ra = kr_find(a), rb = kr_find(b);
    if (ra == rb) return 0;
    if (kr_rank[ra] < kr_rank[rb]) { int t = ra; ra = rb; rb = t; }
    kr_parent[rb] = ra;
    if (kr_rank[ra] == kr_rank[rb]) kr_rank[ra]++;
    return 1;
}

/* ── Kruskal ──────────────────────────────────────────────────────────────── */

typedef struct { int u, v, w; } KrEdge;

static KrEdge kr_edges[KR_NE] = {
    {0,1,1},{1,2,2},{2,3,3},{0,2,4},{1,3,5},{3,4,6},{0,3,7},{2,4,8}
};

static void kruskal(int *mst_weight_out, int *mst_edges_out)
{
    /* Insertion sort by weight (already sorted in this fixture) */
    for (int i = 1; i < KR_NE; i++) {
        KrEdge key = kr_edges[i];
        int j = i - 1;
        while (j >= 0 && kr_edges[j].w > key.w) { kr_edges[j+1] = kr_edges[j]; j--; }
        kr_edges[j+1] = key;
    }

    kr_init();
    int mw = 0, me = 0;
    for (int i = 0; i < KR_NE && me < KR_N - 1; i++) {
        if (kr_union(kr_edges[i].u, kr_edges[i].v)) {
            mw += kr_edges[i].w;
            me++;
        }
    }
    *mst_weight_out = mw;
    *mst_edges_out  = me;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_kruskal(void)
{
    int mst_weight, mst_edges;
    kruskal(&mst_weight, &mst_edges);
    /* mst_weight=12, mst_edges=4 */

    g_result = ((uint32_t)KR_N << 16)
             | ((uint32_t)mst_weight << 8)
             | (uint32_t)mst_edges;
}

__attribute__((noreturn)) void _start(void)
{
    test_kruskal();
    for (;;);
}
