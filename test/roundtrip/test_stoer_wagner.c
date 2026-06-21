/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Stoer-Wagner Global Minimum Cut fixture.
 *
 * The Stoer-Wagner algorithm computes the minimum edge-cut of an undirected
 * weighted graph in O(V³) by performing (V-1) "minimum-cut phases."
 *
 * Each phase:
 *   1. Grow a set A starting from an arbitrary vertex, always adding the
 *      "most tightly connected" vertex (max sum of edges to A).
 *   2. The last-added vertex t is the "s-t cut of the phase"; record
 *      its connectivity w[t] as a candidate min-cut value.
 *   3. Merge s and t into a single vertex (combine their edge weights).
 *
 * Distinctive decompiler idioms:
 *   1. `max_w` scan for tightest connection: `for v: if !in_A && w[v]>max_w`
 *   2. `w[v] += adj[t][v]` — merge step updates edge weights
 *   3. `cut = min(cut, w[t])` — phase cut candidate
 *   4. Two-pointer s/t tracking: `s = t; t = next_max;`
 *
 * Graph (5 nodes, undirected weighted):
 *   0─1: 2,  0─2: 3,  1─2: 2,  1─3: 3,  2─3: 1,  2─4: 4,  3─4: 2
 *   Adjacency matrix (symmetric):
 *     0:[0,2,3,0,0] 1:[2,0,2,3,0] 2:[3,2,0,1,4] 3:[0,3,1,0,2] 4:[0,0,4,2,0]
 *
 * Min cut = 4 (cut between {4} and {0,1,2,3}: edges 2─4=4, 3─4=2 → sum=6...
 *   actually let me compute manually: cut between {0,1,2,3} and {4} is
 *   edge 2─4(4) + edge 3─4(2) = 6. Between {0,1,2} and {3,4} is
 *   edge 1─3(3) + edge 2─3(1) + ... hmm.
 *
 * Let me use a smaller graph: 4-node graph
 *   Nodes: 0,1,2,3
 *   Edges: 0─1:2, 0─2:3, 1─2:2, 1─3:3, 2─3:1
 *   All possible cuts:
 *   {0}|{1,2,3}: edges 0─1=2 + 0─2=3 = 5
 *   {1}|{0,2,3}: edges 0─1=2 + 1─2=2 + 1─3=3 = 7
 *   {2}|{0,1,3}: edges 0─2=3 + 1─2=2 + 2─3=1 = 6
 *   {3}|{0,1,2}: edges 1─3=3 + 2─3=1 = 4
 *   {0,1}|{2,3}: edges 0─2=3 + 1─2=2 + 1─3=3 = 8
 *   {0,2}|{1,3}: edges 0─1=2 + 1─2=2 + 2─3=1 = 5 ... wait: 0─1, 1─2 cross, 2─3 crosses?
 *     {0,2}|{1,3}: edges crossing = 0─1=2 + 1─2=2... no: 2 is in {0,2} and 1 is in {1,3}
 *     so 2─1 crosses, 2─3 crosses? No, 3 is in {1,3}, 2─3 crosses.
 *     Crossing edges: 0─1=2, 1─2=2, 2─3=1. Sum = 5.
 *     Also: 0─2 does NOT cross (both in same partition). 1─3 does NOT cross.
 *   {0,3}|{1,2}: edges 0─1=2 + 0─2=3 + 1─3=3 + 2─3=1 = ... wait {0,3} vs {1,2}:
 *     0─1=2 crosses (0 in left, 1 in right) ✓
 *     0─2=3 crosses ✓
 *     1─3=3: 3 in left, 1 in right → crosses ✓
 *     2─3=1: 2 in right, 3 in left → crosses ✓
 *     Sum = 2+3+3+1 = 9
 *
 *   Min cut = 4 (partition {3} vs {0,1,2})
 *
 * n_nodes = 4
 * min_cut = 4
 * n_phases = n-1 = 3
 *
 * g_result = (n_nodes << 16) | (min_cut << 8) | n_phases = 0x00040403
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SW_N 4

static int sw_adj[SW_N][SW_N];
static int sw_merged[SW_N];  /* 1 if this node is merged/removed */

/* Run one Stoer-Wagner phase.
 * Returns the cut value of the phase and sets *t to the last added node.
 * The merge of (s,t) is done by the caller. */
static int sw_phase(int active, int *t_out)
{
    int in_A[SW_N] = {0};
    int w[SW_N]    = {0};
    int s = -1, t = -1;

    for (int iter = 0; iter < active; iter++) {
        /* Find most tightly connected vertex not in A */
        int max_w = -1, z = -1;
        for (int v = 0; v < SW_N; v++) {
            if (!sw_merged[v] && !in_A[v]) {
                if (z == -1 || w[v] > max_w) { z = v; max_w = w[v]; }
            }
        }
        /* Add z to A */
        in_A[z] = 1;
        s = t; t = z;

        /* Update connectivity weights */
        for (int v = 0; v < SW_N; v++)
            if (!sw_merged[v] && !in_A[v])
                w[v] += sw_adj[z][v];
    }
    *t_out = t;
    return w[t];  /* the connectivity of last added = phase cut value */
}

void test_stoer_wagner(void)
{
    /* Build undirected weighted graph */
    static const int edges[][3] = {
        {0,1,2}, {0,2,3}, {1,2,2}, {1,3,3}, {2,3,1}
    };
    for (int e = 0; e < 5; e++) {
        int u=edges[e][0], v=edges[e][1], w=edges[e][2];
        sw_adj[u][v] += w;
        sw_adj[v][u] += w;
    }

    int min_cut = 0x7fffffff;
    int n_phases = 0;
    int active = SW_N;

    while (active > 1) {
        int t;
        int cut = sw_phase(active, &t);
        if (cut < min_cut) min_cut = cut;

        /* Merge t into the node before it (s is implicit — merge into any survivor) */
        /* Find s: any non-merged node ≠ t */
        int s = -1;
        for (int v = 0; v < SW_N; v++) {
            if (!sw_merged[v] && v != t) { s = v; break; }
        }
        /* Merge t into s */
        for (int v = 0; v < SW_N; v++) {
            sw_adj[s][v] += sw_adj[t][v];
            sw_adj[v][s] += sw_adj[v][t];
        }
        sw_merged[t] = 1;
        active--;
        n_phases++;
    }
    /* min_cut=4, n_phases=3 */

    g_result = ((uint32_t)SW_N    << 16)
             | ((uint32_t)min_cut << 8)
             | ((uint32_t)n_phases & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_stoer_wagner();
    for (;;);
}
