/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Tarjan's Strongly Connected Components fixture.
 *
 * Tarjan's linear-time SCC algorithm using DFS with discovery time (disc[]),
 * low-link values (low[]), and an on-stack flag (on_stk[]).
 *
 * Distinctive decompiler idioms:
 *   1. `low[v] = min(low[v], disc[u])` — back-edge updates low-link
 *   2. `if (disc[u] == -1) { dfs(u); low[v] = min(low[v], low[u]); }` — tree edge
 *   3. `if (low[v] == disc[v])` — root of SCC detected
 *   4. Pop stack until v to form an SCC
 *
 * Graph: 5 nodes (0..4)
 *   Edges: 0→1, 1→2, 2→0, 2→3, 3→4, 4→3
 *
 * SCCs (in discovery order):
 *   SCC0: {3, 4} — size 2  (discovered first from 3's subtree)
 *   SCC1: {2, 1, 0} — size 3  (root 0 is detected last)
 *
 * n_nodes   = 5
 * n_scc     = 2
 * xor_sizes = 2 ^ 3 = 1
 *
 * g_result = (n_nodes << 16) | (n_scc << 8) | xor_sizes = 0x00050201
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph ───────────────────────────────────────────────────────────────── */

#define TJ_N  5

static const int tj_adj_init[TJ_N][2] = {{1,-1},{2,-1},{0,3},{4,-1},{3,-1}};
static const int tj_deg_init[TJ_N]    = {1, 1, 2, 1, 1};

static int tj_adj[TJ_N][2];
static int tj_deg[TJ_N];

/* ── Tarjan state ────────────────────────────────────────────────────────── */

static int tj_disc[TJ_N];
static int tj_low[TJ_N];
static int tj_stk[TJ_N];
static int tj_on_stk[TJ_N];
static int tj_timer;
static int tj_stk_top;
static int tj_n_scc;
static int tj_scc_size[TJ_N];

/* ── DFS ─────────────────────────────────────────────────────────────────── */

static void tarjan_dfs(int v)
{
    tj_disc[v] = tj_low[v] = tj_timer++;
    tj_stk[tj_stk_top++] = v;
    tj_on_stk[v] = 1;

    for (int i = 0; i < tj_deg[v]; i++) {
        int u = tj_adj[v][i];
        if (tj_disc[u] == -1) {
            tarjan_dfs(u);
            if (tj_low[u] < tj_low[v]) tj_low[v] = tj_low[u];
        } else if (tj_on_stk[u]) {
            if (tj_disc[u] < tj_low[v]) tj_low[v] = tj_disc[u];
        }
    }

    if (tj_low[v] == tj_disc[v]) {
        int scc = tj_n_scc++;
        tj_scc_size[scc] = 0;
        int u;
        do {
            u = tj_stk[--tj_stk_top];
            tj_on_stk[u] = 0;
            tj_scc_size[scc]++;
        } while (u != v);
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_tarjan_scc(void)
{
    for (int i = 0; i < TJ_N; i++) {
        tj_deg[i]  = tj_deg_init[i];
        tj_adj[i][0] = tj_adj_init[i][0];
        tj_adj[i][1] = tj_adj_init[i][1];
        tj_disc[i] = -1;
        tj_on_stk[i] = 0;
    }
    tj_timer = 0; tj_stk_top = 0; tj_n_scc = 0;

    for (int i = 0; i < TJ_N; i++)
        if (tj_disc[i] == -1) tarjan_dfs(i);

    uint32_t xor_sizes = 0;
    for (int i = 0; i < tj_n_scc; i++)
        xor_sizes ^= (uint32_t)tj_scc_size[i];

    /* n_scc=2, sizes={2,3}, xor=1 */
    g_result = ((uint32_t)TJ_N << 16) | ((uint32_t)tj_n_scc << 8) | (xor_sizes & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_tarjan_scc();
    for (;;);
}
