/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Maximum Clique (Bitmask Brute Force) fixture.
 *
 * For small n, enumerate all 2^n subsets and find the largest complete subgraph.
 * A subset S is a clique iff ∀u,v ∈ S: adj[u][v]=1.
 *
 * Distinctive decompiler idioms:
 *   1. `for (S=0; S<(1<<n); S++)` — enumerate all 2^n subsets
 *   2. `if (popcount(S) <= mc) continue` — prune non-improving subsets
 *   3. `for (u=0; u<n; u++) if (S>>u&1) for (v=u+1; v<n; v++) if (S>>v&1)` — pairs in S
 *   4. `if (!adj[u][v]) { ok=0; break; }` — non-edge ⇒ not a clique
 *   5. `mc = popcount(S)` — update max clique size on success
 *
 * Graph: n=6 nodes, 7 edges
 *   Clique K4 on nodes {0,1,2,3}: edges 0-1, 0-2, 0-3, 1-2, 1-3, 2-3
 *   Additional edge: 4-5
 *   Max clique = {0,1,2,3} of size 4
 *   Nodes 4,5 form a clique of size 2 only
 *
 * n_nodes    = 6  = 0x06
 * n_edges    = 7  = 0x07
 * max_clique = 4  = 0x04
 *
 * g_result = (n_nodes << 16) | (n_edges << 8) | max_clique = 0x060704
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CL_N 6

static int cl_adj[CL_N][CL_N];

static int cl_pop(int x) { int c=0; for (; x; x>>=1) c+=x&1; return c; }

void test_max_clique(void)
{
    static const int edges[][2] = {
        {0,1},{0,2},{0,3},{1,2},{1,3},{2,3},{4,5}
    };
    int ne = 7;
    for (int i = 0; i < ne; i++) {
        cl_adj[edges[i][0]][edges[i][1]] = 1;
        cl_adj[edges[i][1]][edges[i][0]] = 1;
    }

    int mc = 0;
    for (int S = 0; S < (1 << CL_N); S++) {
        if (cl_pop(S) <= mc) continue;
        int ok = 1;
        for (int u = 0; u < CL_N && ok; u++) {
            if (!(S >> u & 1)) continue;
            for (int v = u + 1; v < CL_N && ok; v++) {
                if (!(S >> v & 1)) continue;
                if (!cl_adj[u][v]) ok = 0;
            }
        }
        if (ok) mc = cl_pop(S);
    }
    /* mc=4 ({0,1,2,3}) */

    g_result = ((uint32_t)CL_N << 16)
             | ((uint32_t)ne   << 8)
             | ((uint32_t)mc & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_max_clique();
    for (;;);
}
