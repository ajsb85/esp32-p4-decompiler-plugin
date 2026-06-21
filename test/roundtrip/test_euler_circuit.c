/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Euler Circuit (Hierholzer's algorithm) fixture.
 *
 * An Euler circuit visits every edge exactly once and returns to the start.
 * Existence condition: all vertices have even degree.
 * Hierholzer's algorithm: follow edges greedily; when stuck, splice a new
 * sub-circuit starting from the last vertex with unused edges.
 *
 * Distinctive decompiler idioms:
 *   1. `if (deg[v] % 2 != 0) has_euler = 0` — check all-even degrees
 *   2. `while (stack not empty): v = top; find unused edge from v;`
 *      `if found: mark used, push neighbor; else: pop to circuit`
 *   3. `ec_used[v][i] = 1; mark_reverse(u, v)` — undirected edge used
 *   4. `circuit_len == n_edges + 1` — circuit visits n_edges+1 nodes
 *
 * Graph: 5 nodes, 6 edges (two triangles sharing vertex 2)
 *   Edges: 0-1, 1-2, 2-0, 2-3, 3-4, 4-2
 *   Degrees: 0=2, 1=2, 2=4, 3=2, 4=2  ← all even → Euler circuit exists
 *
 * Hierholzer from node 0 produces circuit: 0→1→2→4→3→2→0 (or similar)
 * Circuit length = 7 nodes (6 edges traversed + return to start)
 *
 * n_nodes       = 5
 * n_edges       = 6
 * has_euler_cir = 1  (all degrees even)
 *
 * g_result = (n_nodes << 16) | (n_edges << 8) | has_euler_cir = 0x00050601
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph ───────────────────────────────────────────────────────────────── */

#define EC_N 5
#define EC_E 6

static const int ec_adj_init[EC_N][4] = {
    {1, 2, -1, -1},   /* 0: connects to 1, 2 */
    {0, 2, -1, -1},   /* 1: connects to 0, 2 */
    {0,  1,  3,  4},  /* 2: connects to 0, 1, 3, 4 */
    {2,  4, -1, -1},  /* 3: connects to 2, 4 */
    {2,  3, -1, -1}   /* 4: connects to 2, 3 */
};
static const int ec_deg_init[EC_N] = {2, 2, 4, 2, 2};

static int ec_adj[EC_N][4];
static int ec_deg[EC_N];
static int ec_used[EC_N][4]; /* edge-used flags */

/* ── Hierholzer ──────────────────────────────────────────────────────────── */

static int ec_stk[EC_E + 2];
static int ec_circuit[EC_E + 2];
static int ec_clen;

static void hierholzer(int start)
{
    int stop = 0;
    ec_clen = 0;
    ec_stk[stop++] = start;

    while (stop > 0) {
        int v = ec_stk[stop - 1];
        int found = 0;
        for (int i = 0; i < ec_deg[v]; i++) {
            if (!ec_used[v][i]) {
                int u = ec_adj[v][i];
                ec_used[v][i] = 1;
                /* mark reverse edge to avoid re-using undirected edge */
                for (int j = 0; j < ec_deg[u]; j++) {
                    if (ec_adj[u][j] == v && !ec_used[u][j]) {
                        ec_used[u][j] = 1;
                        break;
                    }
                }
                ec_stk[stop++] = u;
                found = 1;
                break;
            }
        }
        if (!found) ec_circuit[ec_clen++] = ec_stk[--stop];
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_euler_circuit(void)
{
    for (int i = 0; i < EC_N; i++) {
        ec_deg[i] = ec_deg_init[i];
        for (int j = 0; j < 4; j++) {
            ec_adj[i][j] = ec_adj_init[i][j];
            ec_used[i][j] = 0;
        }
    }

    /* Check all degrees are even */
    int has_euler = 1;
    for (int i = 0; i < EC_N; i++)
        if (ec_deg[i] % 2 != 0) has_euler = 0;

    hierholzer(0);

    /* has_euler=1 (circuit_len=7 = EC_E+1 edges traversed) */
    g_result = ((uint32_t)EC_N << 16)
             | ((uint32_t)EC_E << 8)
             | (uint32_t)has_euler;
}

__attribute__((noreturn)) void _start(void)
{
    test_euler_circuit();
    for (;;);
}
