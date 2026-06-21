/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Breadth-First Search (BFS) round-trip fixture.
 *
 * BFS on a static 7-node binary-tree-shaped undirected graph stored as an
 * adjacency matrix.  Computes shortest-path distances from source 0.
 *
 * Graph (edges):
 *   0-1, 0-2, 1-3, 1-4, 2-5, 3-6
 *
 *   Tree shape:
 *         0
 *        / \
 *       1   2
 *      / \   \
 *     3   4   5
 *    /
 *   6
 *
 * BFS from node 0 — visit order: 0, 1, 2, 3, 4, 5, 6
 * Shortest distances: dist = {0, 1, 1, 2, 2, 2, 3}
 *   sum_dist = 0+1+1+2+2+2+3 = 11 = 0x0B
 *   xor_dist = 0^1^1^2^2^2^3 = 1
 *   n_visited = 7
 *
 * g_result = (n_visited << 16) | (sum_dist << 8) | xor_dist = 0x00070B01
 *
 * Recognizable decompiler idioms:
 *   q[tail++] = u; v = q[head++];   ← queue enqueue / dequeue
 *   if (dist[u] < 0)                ← unvisited check
 *   dist[u] = dist[v] + 1;          ← BFS distance relaxation
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph (adjacency matrix, 7 nodes) ───────────────────────────────────── */

#define N_NODES 7

static const int gadj[N_NODES][N_NODES] = {
    /*       0  1  2  3  4  5  6 */
    /* 0 */ {0, 1, 1, 0, 0, 0, 0},
    /* 1 */ {1, 0, 0, 1, 1, 0, 0},
    /* 2 */ {1, 0, 0, 0, 0, 1, 0},
    /* 3 */ {0, 1, 0, 0, 0, 0, 1},
    /* 4 */ {0, 1, 0, 0, 0, 0, 0},
    /* 5 */ {0, 0, 1, 0, 0, 0, 0},
    /* 6 */ {0, 0, 0, 1, 0, 0, 0},
};

/* ── BFS ─────────────────────────────────────────────────────────────────── */

static int bfs_dist[N_NODES];
static int bfs_queue[N_NODES];

static void bfs(int src)
{
    for (int i = 0; i < N_NODES; i++)
        bfs_dist[i] = -1;

    int head = 0, tail = 0;
    bfs_dist[src] = 0;
    bfs_queue[tail++] = src;

    while (head < tail) {
        int v = bfs_queue[head++];
        for (int u = 0; u < N_NODES; u++) {
            if (gadj[v][u] && bfs_dist[u] < 0) {
                bfs_dist[u] = bfs_dist[v] + 1;
                bfs_queue[tail++] = u;
            }
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_bfs(void)
{
    bfs(0);

    int n_visited = 0;
    uint32_t sum_d = 0, xor_d = 0;
    for (int i = 0; i < N_NODES; i++) {
        if (bfs_dist[i] >= 0) {
            n_visited++;
            sum_d += (uint32_t)bfs_dist[i];
            xor_d ^= (uint32_t)bfs_dist[i];
        }
    }

    g_result = ((uint32_t)n_visited << 16)
             | (sum_d << 8)
             | (xor_d & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_bfs();
    for (;;);
}
