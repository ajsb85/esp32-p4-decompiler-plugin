/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Topological sort (Kahn's algorithm) round-trip fixture.
 *
 * Kahn's BFS-based topological sort on a 6-node directed acyclic graph.
 * Nodes with in-degree 0 are queued in ascending node-id order.
 *
 * Directed edges (adjacency matrix):
 *   4 → 0, 4 → 1
 *   5 → 0, 5 → 2
 *   2 → 3
 *   3 → 1
 *
 * In-degrees: {2, 2, 1, 1, 0, 0}
 *
 * Kahn's execution trace (FIFO queue, nodes added in ascending v order):
 *   Initial queue: [4, 5]  (in-degree 0)
 *   Pop 4 → topo[0]=4. Decrement indeg[0]→1, indeg[1]→1. Nothing new.
 *   Pop 5 → topo[1]=5. Decrement indeg[0]→0 (add 0), indeg[2]→0 (add 2). Queue:[0,2]
 *   Pop 0 → topo[2]=0. No outgoing.
 *   Pop 2 → topo[3]=2. Decrement indeg[3]→0 (add 3). Queue:[3]
 *   Pop 3 → topo[4]=3. Decrement indeg[1]→0 (add 1). Queue:[1]
 *   Pop 1 → topo[5]=1. No outgoing.
 *
 * Topological order: [4, 5, 0, 2, 3, 1]
 *   sum  = 4+5+0+2+3+1 = 15 = 0x0F
 *   xor  = 4^5^0^2^3^1 = 1
 *   n    = 6
 *
 * g_result = (n << 16) | (sum << 8) | xor = 0x00060F01
 *
 * Recognizable decompiler idioms:
 *   indeg[v]--; if (indeg[v] == 0) queue[tail++] = v;  ← in-degree decrement + queue
 *   while (head < tail) { u = queue[head++]; ... }     ← BFS main loop
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph (6 nodes, directed) ───────────────────────────────────────────── */

#define TOPO_N 6

static const int tadj[TOPO_N][TOPO_N] = {
    /*       0  1  2  3  4  5 */
    /* 0 → */{0, 0, 0, 0, 0, 0},
    /* 1 → */{0, 0, 0, 0, 0, 0},
    /* 2 → */{0, 0, 0, 1, 0, 0},
    /* 3 → */{0, 1, 0, 0, 0, 0},
    /* 4 → */{1, 1, 0, 0, 0, 0},
    /* 5 → */{1, 0, 1, 0, 0, 0},
};

/* ── Kahn's algorithm ─────────────────────────────────────────────────────── */

static int topo_indeg[TOPO_N];
static int topo_queue[TOPO_N];
static int topo_order[TOPO_N];

static void kahn_sort(void)
{
    /* Compute in-degrees. */
    for (int i = 0; i < TOPO_N; i++)
        topo_indeg[i] = 0;
    for (int u = 0; u < TOPO_N; u++)
        for (int v = 0; v < TOPO_N; v++)
            if (tadj[u][v])
                topo_indeg[v]++;

    /* Seed queue with all in-degree-0 nodes (ascending order). */
    int head = 0, tail = 0, n_sorted = 0;
    for (int i = 0; i < TOPO_N; i++)
        if (topo_indeg[i] == 0)
            topo_queue[tail++] = i;

    /* Main BFS loop. */
    while (head < tail) {
        int u = topo_queue[head++];
        topo_order[n_sorted++] = u;
        for (int v = 0; v < TOPO_N; v++) {
            if (tadj[u][v]) {
                topo_indeg[v]--;
                if (topo_indeg[v] == 0)
                    topo_queue[tail++] = v;
            }
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_toposort(void)
{
    kahn_sort();

    uint32_t sum_t = 0, xor_t = 0;
    for (int i = 0; i < TOPO_N; i++) {
        sum_t += (uint32_t)topo_order[i];
        xor_t ^= (uint32_t)topo_order[i];
    }

    g_result = ((uint32_t)TOPO_N << 16)
             | (sum_t << 8)
             | (xor_t & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_toposort();
    for (;;);
}
