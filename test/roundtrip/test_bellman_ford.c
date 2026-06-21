/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Bellman-Ford SSSP round-trip fixture.
 *
 * Single-source shortest paths via Bellman-Ford on a 5-node directed graph
 * with negative-weight edges (no negative cycle).  Runs n-1 relaxation
 * passes then a final pass to detect negative cycles.
 *
 * Edges (u→v, weight):
 *   0→1 (+6),  0→2 (+7)
 *   1→2 (+8),  1→3 (-4),  1→4 (+5)
 *   2→4 (-3)
 *   3→0 (+2)
 *   4→3 (+7)
 *
 * Relaxation from source node 0:
 *   Pass 1 (first edge ordering above):
 *     0→1: d[1] = 6
 *     0→2: d[2] = 7
 *     1→2: 6+8=14 > 7 — no change
 *     1→3: 6-4=2  → d[3] = 2
 *     1→4: 6+5=11 → d[4] = 11
 *     2→4: 7-3=4  → d[4] = 4
 *     3→0: 2+2=4  > 0 — no change
 *     4→3: 4+7=11 > 2 — no change
 *   Passes 2-4: no further relaxations.
 *
 * Shortest distances: {0, 6, 7, 2, 4}
 *   sum_dist = 0+6+7+2+4 = 19 = 0x13
 *   xor_dist = 0^6^7^2^4 = 7
 *   n = 5
 *   neg_cycle = 0 (no negative cycle detected)
 *
 * g_result = (n << 16) | (sum_dist << 8) | xor_dist = 0x00051307
 *
 * Recognizable decompiler idioms:
 *   for (p=0; p<n-1; p++)                              ← n-1 pass loop
 *     for (e=0; e<n_edges; e++)                        ← edge scan
 *       if (d[u]+w < d[v]) d[v] = d[u]+w;             ← relaxation
 *   for (e=0; e<n_edges; e++) if (d[u]+w < d[v]) ...  ← neg-cycle check
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph as edge list ───────────────────────────────────────────────────── */

#define BF_N       5
#define BF_E       8
#define BF_INF     0x7FFF

typedef struct { int u, v, w; } BFEdge;

static const BFEdge bf_edges[BF_E] = {
    {0, 1,  6}, {0, 2,  7},
    {1, 2,  8}, {1, 3, -4}, {1, 4,  5},
    {2, 4, -3},
    {3, 0,  2},
    {4, 3,  7},
};

static int bf_dist[BF_N];

/* ── Bellman-Ford ─────────────────────────────────────────────────────────── */

static int bellman_ford(int src)
{
    for (int i = 0; i < BF_N; i++)
        bf_dist[i] = BF_INF;
    bf_dist[src] = 0;

    /* n-1 relaxation passes */
    for (int pass = 0; pass < BF_N - 1; pass++) {
        for (int e = 0; e < BF_E; e++) {
            int u = bf_edges[e].u;
            int v = bf_edges[e].v;
            int w = bf_edges[e].w;
            if (bf_dist[u] != BF_INF && bf_dist[u] + w < bf_dist[v])
                bf_dist[v] = bf_dist[u] + w;
        }
    }

    /* Negative-cycle detection: one more pass */
    for (int e = 0; e < BF_E; e++) {
        int u = bf_edges[e].u;
        int v = bf_edges[e].v;
        int w = bf_edges[e].w;
        if (bf_dist[u] != BF_INF && bf_dist[u] + w < bf_dist[v])
            return 1;   /* negative cycle */
    }
    return 0;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_bellman_ford(void)
{
    int neg_cycle = bellman_ford(0);
    (void)neg_cycle;

    uint32_t sum_d = 0, xor_d = 0;
    for (int i = 0; i < BF_N; i++) {
        sum_d += (uint32_t)bf_dist[i];
        xor_d ^= (uint32_t)bf_dist[i];
    }

    g_result = ((uint32_t)BF_N << 16)
             | (sum_d << 8)
             | (xor_d & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_bellman_ford();
    for (;;);
}
