/* test_disjoint_set_rollback.c — DSU with rollback (offline dynamic connectivity)
 * ESP32-P4 RISC-V: -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O2
 * -ffreestanding -nostdlib -Wall -Werror
 *
 * Rollback DSU (union by rank, no path compression, supports undo).
 * Used in offline dynamic connectivity and divide-and-conquer on intervals.
 * All arithmetic 32-bit only.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_NODES 32
#define MAX_LOG   64   /* max rollback stack depth */

/* ── DSU with rollback ──────────────────────────────────────────────────── */
typedef struct {
    int32_t parent[MAX_NODES];
    int32_t rank[MAX_NODES];
    /* rollback stack: each entry stores (node, old_parent, old_rank_changed_node) */
    int32_t stk_node[MAX_LOG];
    int32_t stk_old_parent[MAX_LOG];
    int32_t stk_rank_node[MAX_LOG];
    int32_t stk_old_rank[MAX_LOG];
    int32_t top;
    int32_t n;
} RollbackDSU;

static RollbackDSU dsu;

static void dsu_init(int32_t n) {
    dsu.n = n;
    dsu.top = 0;
    for (int32_t i = 0; i < n; i++) { dsu.parent[i] = i; dsu.rank[i] = 0; }
}

static int32_t dsu_find(int32_t x) {
    /* No path compression — needed for rollback correctness */
    while (dsu.parent[x] != x) x = dsu.parent[x];
    return x;
}

/* Returns 1 if a merge happened, 0 if already connected */
static int32_t dsu_union(int32_t a, int32_t b) {
    a = dsu_find(a);
    b = dsu_find(b);
    if (a == b) {
        /* Record no-op so rollback stack stays consistent */
        dsu.stk_node[dsu.top]       = -1;
        dsu.stk_old_parent[dsu.top] = -1;
        dsu.stk_rank_node[dsu.top]  = -1;
        dsu.stk_old_rank[dsu.top]   = -1;
        dsu.top++;
        return 0;
    }
    /* Union by rank */
    if (dsu.rank[a] < dsu.rank[b]) { int32_t t = a; a = b; b = t; }
    /* b becomes child of a */
    dsu.stk_node[dsu.top]       = b;
    dsu.stk_old_parent[dsu.top] = dsu.parent[b];
    dsu.stk_rank_node[dsu.top]  = a;
    dsu.stk_old_rank[dsu.top]   = dsu.rank[a];
    dsu.top++;
    dsu.parent[b] = a;
    if (dsu.rank[a] == dsu.rank[b]) dsu.rank[a]++;
    return 1;
}

/* Rollback one union */
static void dsu_rollback(void) {
    dsu.top--;
    int32_t b = dsu.stk_node[dsu.top];
    if (b == -1) return; /* was a no-op */
    dsu.parent[b] = dsu.stk_old_parent[dsu.top];
    int32_t a = dsu.stk_rank_node[dsu.top];
    dsu.rank[a]   = dsu.stk_old_rank[dsu.top];
}

static int32_t dsu_same(int32_t a, int32_t b) { return dsu_find(a) == dsu_find(b); }

/* Save/restore checkpoint via stack depth */
static int32_t dsu_save(void) { return dsu.top; }

static void dsu_restore(int32_t checkpoint) {
    while (dsu.top > checkpoint) dsu_rollback();
}

/* ── test driver ─────────────────────────────────────────────────────────*/
void run_dsu_rollback_tests(void) {
    uint32_t n_tests    = 0;
    uint32_t pass_count = 0;
    uint32_t connect_sum = 0;

    /* Test 1: basic union and same-component check */
    {
        n_tests++;
        dsu_init(8);
        dsu_union(0, 1); dsu_union(1, 2); dsu_union(3, 4);
        int ok = dsu_same(0, 2) && !dsu_same(0, 3) && !dsu_same(2, 5);
        if (ok) pass_count++;
    }

    /* Test 2: rollback restores original state */
    {
        n_tests++;
        dsu_init(6);
        int32_t cp = dsu_save();
        dsu_union(0, 1); dsu_union(1, 2);
        dsu_restore(cp);
        int ok = !dsu_same(0, 1) && !dsu_same(1, 2);
        if (ok) pass_count++;
    }

    /* Test 3: nested save/restore */
    {
        n_tests++;
        dsu_init(8);
        dsu_union(0, 1);
        int32_t cp1 = dsu_save();
        dsu_union(1, 2); dsu_union(2, 3);
        int32_t cp2 = dsu_save();
        dsu_union(3, 4);
        /* restore to cp2 */
        dsu_restore(cp2);
        int step1 = dsu_same(0,3) && !dsu_same(3,4);
        /* restore to cp1 */
        dsu_restore(cp1);
        int step2 = dsu_same(0,1) && !dsu_same(1,2);
        if (step1 && step2) pass_count++;
    }

    /* Test 4: count connected components after series of unions and rollbacks */
    {
        n_tests++;
        dsu_init(16);
        /* Connect even nodes together */
        for (int i = 0; i < 14; i += 2) dsu_union(i, i+2);
        /* Connect odd nodes together */
        int32_t cp = dsu_save();
        for (int i = 1; i < 14; i += 2) dsu_union(i, i+2);
        /* Count components after full union */
        int comp_full = 0;
        for (int i = 0; i < 16; i++) if (dsu_find(i) == i) comp_full++;
        /* Rollback odd unions */
        dsu_restore(cp);
        int comp_after = 0;
        for (int i = 0; i < 16; i++) if (dsu_find(i) == i) comp_after++;
        connect_sum += (uint32_t)(comp_full + comp_after);
        if (comp_full == 2 && comp_after == 9) pass_count++;
    }

    /* Test 5: union same element (no-op), rollback should still work */
    {
        n_tests++;
        dsu_init(4);
        dsu_union(0,1);
        int32_t cp = dsu_save();
        dsu_union(0,1); /* already same */
        dsu_union(2,3);
        dsu_restore(cp);
        int ok = dsu_same(0,1) && !dsu_same(2,3);
        if (ok) pass_count++;
    }

    uint8_t n_t = (uint8_t)(n_tests  & 0xFF);
    uint8_t m_a = (uint8_t)(pass_count & 0xFF);
    uint8_t m_b = (uint8_t)(connect_sum & 0xFF);
    if (m_a == 0) m_a = 0x3C;
    if (m_b == 0) m_b = 0x4B;
    if (m_b == m_a) m_b ^= 0x17;
    g_result = ((uint32_t)n_t << 16) | ((uint32_t)m_a << 8) | (uint32_t)m_b;
}

void _start(void) {
    run_dsu_rollback_tests();
    while (1) {}
}
