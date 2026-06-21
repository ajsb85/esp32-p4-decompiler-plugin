/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — 2-SAT (Two-Satisfiability) fixture.
 *
 * 2-SAT reduces a CNF formula with only 2-literal clauses to strongly-
 * connected-component (SCC) analysis of an implication graph.
 *
 * Encoding:
 *   Variable k → node 2k (positive literal) and 2k+1 (negative literal)
 *   Clause (a OR b) → implication (NOT a → b) AND (NOT b → a)
 *   NOT of node v → v ^ 1  (XOR 1 flips last bit)
 *
 * Satisfiability: UNSAT iff any variable k has comp[2k] == comp[2k+1].
 * Assignment: x_k = TRUE iff comp[2k] < comp[2k+1]  (Tarjan ordering where
 *   lower comp = found earlier = sink of condensation = assigned true).
 *
 * Distinctive decompiler idioms:
 *   1. `not_v = v ^ 1` — complement via XOR (instead of v+n)
 *   2. `g_ts[na][b]=1; g_ts[nb][a]=1;` — two implications per clause
 *   3. Tarjan DFS: `low[u] = min(low[u], low[v])` after child return
 *   4. SCC root: `if (low[u] == disc[u]) { pop until u }`
 *   5. Assignment: `result |= (comp[2k] < comp[2k+1]) << k`
 *
 * Formula (3 variables, 3 clauses):
 *   (x0 OR x1) AND (NOT x0 OR x2) AND (x1 OR NOT x2)
 *
 * Implication graph (6 nodes):
 *   NOT x0→x1 (1→2), NOT x1→x0 (3→0)        — from clause 1
 *   x0→x2    (0→4), NOT x2→NOT x0 (5→1)       — from clause 2
 *   NOT x1→NOT x2 (3→5), x2→x1 (4→2)          — from clause 3
 *
 * Satisfying assignment: x0=TRUE, x1=TRUE, x2=TRUE  → bitmask = 0b111 = 7
 *
 * g_result = (n_vars << 16) | (is_sat << 8) | assignment = 0x00030107
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TS_N  6   /* 2 * n_vars */

static int ts_g[TS_N][TS_N];
static int ts_disc[TS_N], ts_low[TS_N], ts_in_stk[TS_N];
static int ts_stk[TS_N], ts_stk_top;
static int ts_comp[TS_N];
static int ts_n_comps, ts_timer;

/* ── Tarjan SCC DFS ───────────────────────────────────────────────────────── */

static void tarjan_dfs(int u)
{
    ts_disc[u] = ts_low[u] = ++ts_timer;
    ts_stk[ts_stk_top++] = u;
    ts_in_stk[u] = 1;

    for (int v = 0; v < TS_N; v++) {
        if (!ts_g[u][v]) continue;
        if (!ts_disc[v]) {
            tarjan_dfs(v);
            if (ts_low[v] < ts_low[u]) ts_low[u] = ts_low[v];
        } else if (ts_in_stk[v]) {
            if (ts_disc[v] < ts_low[u]) ts_low[u] = ts_disc[v];
        }
    }

    if (ts_low[u] == ts_disc[u]) {
        while (1) {
            int w = ts_stk[--ts_stk_top];
            ts_in_stk[w] = 0;
            ts_comp[w] = ts_n_comps;
            if (w == u) break;
        }
        ts_n_comps++;
    }
}

/* ── Add clause (a OR b) → implications ──────────────────────────────────── */

static void add_clause(int a, int b)
{
    ts_g[a ^ 1][b]     = 1;  /* NOT a → b */
    ts_g[b ^ 1][a]     = 1;  /* NOT b → a */
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_2sat(void)
{
    /* Build implication graph */
    add_clause(0, 2);   /* (x0 OR x1):       NOT x0→x1, NOT x1→x0 */
    add_clause(1, 4);   /* (NOT x0 OR x2):   x0→x2, NOT x2→NOT x0 */
    add_clause(2, 5);   /* (x1 OR NOT x2):   NOT x1→NOT x2, x2→x1 */

    /* Run Tarjan SCC */
    for (int u = 0; u < TS_N; u++)
        if (!ts_disc[u]) tarjan_dfs(u);

    /* Check satisfiability and extract assignment */
    int is_sat = 1, assignment = 0;
    for (int k = 0; k < TS_N / 2; k++) {
        if (ts_comp[2*k] == ts_comp[2*k+1]) { is_sat = 0; break; }
        if (ts_comp[2*k] < ts_comp[2*k+1])  /* lower comp = sink = TRUE */
            assignment |= (1 << k);
    }
    /* is_sat=1, assignment=0b111=7 (x0=x1=x2=TRUE) */

    g_result = (((uint32_t)(TS_N / 2)) << 16)
             | ((uint32_t)is_sat << 8)
             | (uint32_t)assignment;
}

__attribute__((noreturn)) void _start(void)
{
    test_2sat();
    for (;;);
}
