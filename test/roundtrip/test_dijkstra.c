/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Dijkstra's SSSP (linear-scan) round-trip fixture.
 *
 * Single-source shortest path on a 5-node weighted directed graph using
 * a simple O(n²) scan (no heap) — suitable for small graphs on bare-metal.
 *
 * Weighted edges:
 *   0→1 (2), 0→2 (6)
 *   1→2 (3), 1→3 (8)
 *   2→3 (2), 2→4 (5)
 *   3→4 (1)
 *
 * Dijkstra from node 0:
 *   Step 1: pop 0 (d=0). relax 1→2, 2→6.
 *   Step 2: pop 1 (d=2). relax 2→5, 3→10.
 *   Step 3: pop 2 (d=5). relax 3→7, 4→10.
 *   Step 4: pop 3 (d=7). relax 4→8.
 *   Step 5: pop 4 (d=8). Done.
 *
 * Shortest distances: {0, 2, 5, 7, 8}
 *   sum_dist = 0+2+5+7+8 = 22 = 0x16
 *   xor_dist = 0^2^5^7^8 = 8
 *   n = 5
 *
 * g_result = (n << 16) | (sum_dist << 8) | xor_dist = 0x00051608
 *
 * Recognizable decompiler idioms:
 *   for i: if (!visited[i] && dist[i] < min)  ← linear min-scan
 *   if (dist[u] + w[u][v] < dist[v])           ← edge relaxation
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph (adjacency weight matrix, 5 nodes) ────────────────────────────── */

#define DIJK_N 5
#define INF    0x7FFF

static const int dweight[DIJK_N][DIJK_N] = {
    /*     0   1   2   3   4 */
    /* 0 */{0,  2,  6,  0,  0},
    /* 1 */{0,  0,  3,  8,  0},
    /* 2 */{0,  0,  0,  2,  5},
    /* 3 */{0,  0,  0,  0,  1},
    /* 4 */{0,  0,  0,  0,  0},
};

/* ── Dijkstra — O(n²) linear scan ───────────────────────────────────────── */

static int  dijkstra_dist[DIJK_N];
static int  dijkstra_vis[DIJK_N];

static void dijkstra(int src)
{
    for (int i = 0; i < DIJK_N; i++) {
        dijkstra_dist[i] = INF;
        dijkstra_vis[i]  = 0;
    }
    dijkstra_dist[src] = 0;

    for (int step = 0; step < DIJK_N; step++) {
        /* Pick unvisited node with minimum distance. */
        int u = -1;
        for (int i = 0; i < DIJK_N; i++) {
            if (!dijkstra_vis[i] &&
                (u < 0 || dijkstra_dist[i] < dijkstra_dist[u]))
                u = i;
        }
        if (u < 0) break;
        dijkstra_vis[u] = 1;

        /* Relax outgoing edges. */
        for (int v = 0; v < DIJK_N; v++) {
            if (dweight[u][v] > 0) {
                int nd = dijkstra_dist[u] + dweight[u][v];
                if (nd < dijkstra_dist[v])
                    dijkstra_dist[v] = nd;
            }
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_dijkstra(void)
{
    dijkstra(0);

    uint32_t sum_d = 0, xor_d = 0;
    for (int i = 0; i < DIJK_N; i++) {
        sum_d += (uint32_t)dijkstra_dist[i];
        xor_d ^= (uint32_t)dijkstra_dist[i];
    }

    g_result = ((uint32_t)DIJK_N << 16)
             | (sum_d << 8)
             | (xor_d & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_dijkstra();
    for (;;);
}
