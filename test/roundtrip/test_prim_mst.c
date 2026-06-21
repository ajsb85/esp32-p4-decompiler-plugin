/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Prim's Minimum Spanning Tree (O(n²)) fixture.
 *
 * Dense-graph Prim's using an adjacency matrix and a key[] array.
 * Classic O(n²) implementation (no priority queue):
 *
 *   key[0]=0; key[v]=INF for v>0; in_mst[v]=false
 *   repeat n times:
 *     u = argmin key[v] where v not in MST
 *     in_mst[u] = true
 *     for each v: if adj[u][v] && !in_mst[v] && adj[u][v] < key[v]: key[v] = adj[u][v]
 *
 * Input (n=5 undirected weighted graph):
 *   0-1:2, 0-3:6, 1-2:3, 1-3:8, 1-4:5, 2-4:7, 3-4:9
 *
 * Prim trace from vertex 0:
 *   Pick 0(0) → update: key[1]=2, key[3]=6
 *   Pick 1(2) → update: key[2]=3, key[4]=5
 *   Pick 2(3) → no better updates
 *   Pick 4(5) → no better updates
 *   Pick 3(6)
 *
 *   MST edges: 0-1(2), 1-2(3), 1-4(5), 0-3(6)
 *   mst_weight = 2+3+5+6 = 16 = 0x10
 *   n_edges    = n-1 = 4
 *   n          = 5
 *
 * g_result = (n << 16) | (mst_weight << 8) | n_edges = 0x00051004
 *
 * Recognizable decompiler idioms:
 *   for v: if(!in_mst[v] && (u==-1 || key[v]<key[u])) u=v  ← min-key selection
 *   for v: if(adj[u][v] && !in_mst[v] && adj[u][v]<key[v]): key[v]=adj[u][v]  ← update
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Prim's MST ───────────────────────────────────────────────────────────── */

#define PRIM_N 5
#define PRIM_INF 9999

static const int prim_adj[PRIM_N][PRIM_N] = {
    {0, 2, 0, 6, 0},
    {2, 0, 3, 8, 5},
    {0, 3, 0, 0, 7},
    {6, 8, 0, 0, 9},
    {0, 5, 7, 9, 0},
};

static int prim_key[PRIM_N];
static int prim_in_mst[PRIM_N];

static int prim_mst(void)
{
    for (int v = 0; v < PRIM_N; v++) {
        prim_key[v]    = PRIM_INF;
        prim_in_mst[v] = 0;
    }
    prim_key[0] = 0;

    int total_weight = 0;
    int edges_added  = 0;

    for (int step = 0; step < PRIM_N; step++) {
        /* pick min-key vertex not yet in MST */
        int u = -1;
        for (int v = 0; v < PRIM_N; v++) {
            if (!prim_in_mst[v] && (u == -1 || prim_key[v] < prim_key[u]))
                u = v;
        }
        prim_in_mst[u] = 1;
        if (step > 0) {
            total_weight += prim_key[u];
            edges_added++;
        }
        /* relax neighbors */
        for (int v = 0; v < PRIM_N; v++) {
            if (prim_adj[u][v] && !prim_in_mst[v]
                    && prim_adj[u][v] < prim_key[v])
                prim_key[v] = prim_adj[u][v];
        }
    }
    (void)edges_added;
    return total_weight;   /* = 16 */
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_prim_mst(void)
{
    int mst_w = prim_mst();   /* = 16 */

    g_result = ((uint32_t)PRIM_N << 16)
             | ((uint32_t)mst_w << 8)
             | ((uint32_t)(PRIM_N - 1) & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_prim_mst();
    for (;;);
}
