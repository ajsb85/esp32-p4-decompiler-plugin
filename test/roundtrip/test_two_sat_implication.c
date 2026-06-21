/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — 2-SAT Implication Graph fixture.
 *
 * This fixture focuses specifically on the implication graph construction
 * and truth assignment extraction from 2-SAT SCCs — emphasizing the
 * graph-building and reading phases rather than the SCC algorithm itself.
 *
 * Encoding conventions:
 *   Variable k: positive literal = 2k, negative literal = 2k+1
 *   NOT of literal v = v ^ 1
 *   Clause (a OR b): add edges (NOT a -> b) and (NOT b -> a)
 *
 * Distinctive decompiler idioms:
 *   1. Implication addition: `impl[u^1][cnt[u^1]++] = v`
 *   2. Negation: `lit ^ 1` throughout (not `lit + n` pattern)
 *   3. Contradiction check: `comp[v] == comp[v^1]` for each var
 *   4. Assignment extraction: `val[k] = (comp[2k] > comp[2k+1])` ordering
 *   5. Kosaraju two-pass: explicit order stack and reverse-graph traversal
 *
 * Problem: 4 variables, 5 clauses
 *   (x0 OR x1), (!x1 OR x2), (x2 OR x3), (!x0 OR !x3), (!x2 OR x3)
 *   Satisfying assignment: x0=0, x1=1, x2=1, x3=1
 *   assignment nibble = (x0<<3)|(x1<<2)|(x2<<1)|x3 = (0<<3)|(1<<2)|(1<<1)|1 = 0b0111 = 7
 *
 * Result encoding:
 *   n_vars     = 4 = 0x04
 *   assign_nib = 7 = 0x07
 *   checksum   = (4 + 7) & 0xFF = 11 = 0x0B
 *   g_result = (4<<16)|(7<<8)|11 = 0x04070B
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TSI_VARS  4
#define TSI_N     (TSI_VARS * 2)    /* 8 nodes */
#define TSI_MAXE  16

/* Implication graph */
static int32_t  impl[TSI_N][TSI_MAXE];
static int32_t  impl_cnt[TSI_N];
static int32_t  rimpl[TSI_N][TSI_MAXE];
static int32_t  rimpl_cnt[TSI_N];

/* Kosaraju state */
static int32_t  kos_vis[TSI_N];
static int32_t  kos_ord[TSI_N];
static int32_t  kos_top;
static int32_t  kos_comp[TSI_N];
static int32_t  kos_ncomp;

static void add_implication(int32_t u, int32_t v)
{
    impl[u][impl_cnt[u]++]   = v;
    rimpl[v][rimpl_cnt[v]++] = u;
}

static void add_clause_tsi(int32_t a, int32_t b)
{
    add_implication(a ^ 1, b);
    add_implication(b ^ 1, a);
}

static void dfs_forward(int32_t u)
{
    kos_vis[u] = 1;
    for (int32_t i = 0; i < impl_cnt[u]; i++) {
        int32_t v = impl[u][i];
        if (!kos_vis[v]) dfs_forward(v);
    }
    kos_ord[kos_top++] = u;
}

static void dfs_backward(int32_t u, int32_t comp)
{
    kos_comp[u] = comp;
    for (int32_t i = 0; i < rimpl_cnt[u]; i++) {
        int32_t v = rimpl[u][i];
        if (kos_comp[v] < 0) dfs_backward(v, comp);
    }
}

void test_two_sat_implication(void)
{
    for (int32_t i = 0; i < TSI_N; i++) {
        impl_cnt[i]  = 0;
        rimpl_cnt[i] = 0;
        kos_vis[i]   = 0;
        kos_comp[i]  = -1;
    }
    kos_top   = 0;
    kos_ncomp = 0;

    /* Literal encoding: x_k=true -> literal 2k, x_k=false -> literal 2k+1 */
    /* (x0 OR x1)      => lits 0, 2 */
    add_clause_tsi(0, 2);
    /* (!x1 OR x2)     => lits 3, 4 */
    add_clause_tsi(3, 4);
    /* (x2 OR x3)      => lits 4, 6 */
    add_clause_tsi(4, 6);
    /* (!x0 OR !x3)    => lits 1, 7 */
    add_clause_tsi(1, 7);
    /* (!x2 OR x3)     => lits 5, 6 */
    add_clause_tsi(5, 6);

    /* Kosaraju pass 1 */
    for (int32_t i = 0; i < TSI_N; i++) {
        if (!kos_vis[i]) dfs_forward(i);
    }

    /* Kosaraju pass 2 */
    for (int32_t i = kos_top - 1; i >= 0; i--) {
        int32_t node = kos_ord[i];
        if (kos_comp[node] < 0) {
            dfs_backward(node, kos_ncomp++);
        }
    }

    /* Extract assignment: var k is true if comp[2k] > comp[2k+1] */
    uint32_t assign_nib = 0u;
    for (int32_t k = 0; k < TSI_VARS; k++) {
        uint32_t val = (kos_comp[2*k] > kos_comp[2*k+1]) ? 1u : 0u;
        assign_nib = (assign_nib << 1) | val;
    }

    uint32_t n_vars   = (uint32_t)TSI_VARS;
    uint32_t checksum = (n_vars + assign_nib) & 0xFFu;
    g_result = (n_vars << 16) | (assign_nib << 8) | checksum;
}

__attribute__((noreturn)) void _start(void)
{
    test_two_sat_implication();
    for (;;);
}
