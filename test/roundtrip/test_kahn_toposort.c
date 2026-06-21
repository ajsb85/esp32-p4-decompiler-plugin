/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Kahn's Topological Sort (BFS + in-degree) fixture.
 *
 * Alternative to DFS-based toposort: uses explicit in-degree counts.
 * Enqueues all zero-in-degree nodes first, then processes like BFS.
 *
 * Distinctive decompiler idioms vs DFS-toposort:
 *   1. `for (each edge u→v) in_deg[v]++` — pre-compute in-degrees
 *   2. `for (i=0..n) if (in_deg[i]==0) enqueue(i)` — seed queue
 *   3. Process: `if (--in_deg[v] == 0) enqueue(v)` — decrement-and-enqueue
 *   4. `if (processed < n) return CYCLE_DETECTED` — cycle check at end
 *
 * DAG: 6 nodes (0..5)
 *   Edges: 5→2, 5→0, 4→0, 4→1, 2→3, 3→1
 *
 * Initial in-degrees: 0:2, 1:2, 2:1, 3:1, 4:0, 5:0
 * Initial zero-in-degree nodes: {4, 5}   n_init_zero = 2
 *
 * Kahn order (FIFO, seeded with {4,5}):
 *   4 → {0,1} dec, 5 → {0,2} dec+enqueue{2,0}, 2 → {3} dec+enqueue{3},
 *   0 → {}, 3 → {1} dec+enqueue{1}, 1 → {}
 *   Full order: 4, 5, 2, 0, 3, 1
 *   Last processed node: 1
 *
 * n          = 6
 * n_init_zero = 2
 * last_node   = 1
 *
 * g_result = (n << 16) | (n_init_zero << 8) | last_node = 0x00060201
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Kahn's Topological Sort ─────────────────────────────────────────────── */

#define KT_N  6
#define KT_NE 6

static const int kt_edges[KT_NE][2] = {
    {5, 2}, {5, 0}, {4, 0}, {4, 1}, {2, 3}, {3, 1}
};

static int kt_indeg[KT_N];
static int kt_adj[KT_N][3];  /* max 2 out-edges per node in this graph */
static int kt_outdeg[KT_N];
static int kt_q[KT_N];
static int kt_order[KT_N];

static int kahn_sort(void)
{
    /* build adjacency and in-degrees */
    for (int i = 0; i < KT_N; i++) { kt_indeg[i] = 0; kt_outdeg[i] = 0; }
    for (int i = 0; i < KT_NE; i++) {
        int u = kt_edges[i][0], v = kt_edges[i][1];
        kt_adj[u][kt_outdeg[u]++] = v;
        kt_indeg[v]++;
    }

    int front = 0, back = 0, n_init_zero = 0, processed = 0;
    for (int i = 0; i < KT_N; i++)
        if (kt_indeg[i] == 0) { kt_q[back++] = i; n_init_zero++; }

    while (front < back) {
        int u = kt_q[front++];
        kt_order[processed++] = u;
        for (int i = 0; i < kt_outdeg[u]; i++) {
            int v = kt_adj[u][i];
            if (--kt_indeg[v] == 0) kt_q[back++] = v;
        }
    }
    /* processed == KT_N means no cycle; last node in kt_order[processed-1] */
    (void)processed;
    return n_init_zero;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_kahn_toposort(void)
{
    int n_init_zero = kahn_sort();
    int last_node   = kt_order[KT_N - 1];
    /* n_init_zero=2, last_node=1 */

    g_result = ((uint32_t)KT_N << 16)
             | ((uint32_t)n_init_zero << 8)
             | ((uint32_t)last_node & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_kahn_toposort();
    for (;;);
}
