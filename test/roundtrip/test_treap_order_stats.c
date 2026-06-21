/*
 * test_treap_order_stats.c
 * Treap with Order Statistics (OS-Treap / implicit-key rank queries).
 * Algorithm: A treap is a BST where each node has a random priority and
 *   the tree maintains the max-heap property on priorities.  An order-
 *   statistics treap augments each node with a subtree size field, allowing
 *   O(log N) rank queries (k-th smallest) and order-of (rank of a value).
 *   Operations implemented: insert, delete, k-th smallest, order-of.
 *   Uses simple LCG for node priorities to avoid stdlib dependency.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TOS_MAXNODES 128

typedef struct TosNode {
    int      key;
    uint32_t pri;
    int      sz;
    int      left, right; /* indices into pool, -1 = null */
} TosNode;

static TosNode tos_pool[TOS_MAXNODES];
static int     tos_cnt;
static int     tos_root;

/* LCG pseudo-random for priorities */
static uint32_t tos_rng = 0xDEADBEEFu;
static uint32_t tos_rand(void) {
    tos_rng = tos_rng * 1664525u + 1013904223u;
    return tos_rng;
}

static void tos_reset(void) {
    tos_cnt  = 0;
    tos_root = -1;
    tos_rng  = 0xCAFEBABEu;
}

static int tos_sz(int n) {
    return (n == -1) ? 0 : tos_pool[n].sz;
}

static void tos_upd(int n) {
    if (n != -1)
        tos_pool[n].sz = 1 + tos_sz(tos_pool[n].left) + tos_sz(tos_pool[n].right);
}

static int tos_new(int key) {
    int idx = tos_cnt++;
    tos_pool[idx].key   = key;
    tos_pool[idx].pri   = tos_rand();
    tos_pool[idx].sz    = 1;
    tos_pool[idx].left  = -1;
    tos_pool[idx].right = -1;
    return idx;
}

/* Split by key: left subtree has keys <= k, right has keys > k */
static void tos_split(int n, int k, int *l, int *r) {
    if (n == -1) { *l = *r = -1; return; }
    if (tos_pool[n].key <= k) {
        *l = n;
        tos_split(tos_pool[n].right, k, &tos_pool[n].right, r);
    } else {
        *r = n;
        tos_split(tos_pool[n].left, k, l, &tos_pool[n].left);
    }
    tos_upd(n);
}

/* Merge two treaps (all keys in left < all keys in right) */
static int tos_merge(int l, int r) {
    if (l == -1) return r;
    if (r == -1) return l;
    if (tos_pool[l].pri >= tos_pool[r].pri) {
        tos_pool[l].right = tos_merge(tos_pool[l].right, r);
        tos_upd(l);
        return l;
    } else {
        tos_pool[r].left = tos_merge(l, tos_pool[r].left);
        tos_upd(r);
        return r;
    }
}

static void tos_insert(int key) {
    int l, r;
    tos_split(tos_root, key - 1, &l, &r);
    int nd = tos_new(key);
    tos_root = tos_merge(tos_merge(l, nd), r);
}

static void tos_erase(int key) {
    int l, m, r;
    tos_split(tos_root, key - 1, &l, &r);
    tos_split(r, key, &m, &r);
    /* Drop leftmost node of m (which has key=key) */
    if (m != -1) m = tos_merge(tos_pool[m].left, tos_pool[m].right);
    tos_root = tos_merge(tos_merge(l, m), r);
}

/* k-th smallest (1-indexed) */
static int tos_kth(int n, int k) {
    while (n != -1) {
        int ls = tos_sz(tos_pool[n].left);
        if (k <= ls) { n = tos_pool[n].left; }
        else if (k == ls + 1) { return tos_pool[n].key; }
        else { k -= ls + 1; n = tos_pool[n].right; }
    }
    return -1; /* not found */
}

/* Rank: number of elements <= key */
static int tos_rank(int key) {
    int l, r;
    tos_split(tos_root, key, &l, &r);
    int rank = tos_sz(l);
    tos_root = tos_merge(l, r);
    return rank;
}

static uint32_t run_tos_tests(void) {
    int r1, r2, r3;

    /*
     * Test 1: Insert 5 elements {3,1,4,1,5} (duplicates handled via
     *   split at key-1, so duplicates go to right subtree).
     *   After insert: {1,1,3,4,5} (size 5, note: 1 inserted twice)
     *   k=3rd smallest should be 3, rank of 4 should be 4.
     */
    tos_reset();
    tos_insert(3);
    tos_insert(1);
    tos_insert(4);
    tos_insert(1);
    tos_insert(5);
    r1 = tos_kth(tos_root, 3);  /* expect 3 */

    /*
     * Test 2: Delete one '1', then k=1 should be 1, k=2 should be 3.
     *   Rank of 4 should be 3 (elements <=4: {1,3,4}).
     */
    tos_erase(1);
    r2 = tos_rank(4);  /* expect 3 */

    /*
     * Test 3: Insert {10,20,30,40,50}, k=4 should be 40.
     */
    tos_reset();
    for (int v = 10; v <= 50; v += 10) tos_insert(v);
    r3 = tos_kth(tos_root, 4);  /* expect 40 */

    /*
     * Pack:
     *   n_tests  = 3
     *   metric_a = r1 + r2 = 3 + 3 = 6
     *   metric_b = r3 / 8 = 40/8 = 5
     *   Bytes: 3, 6, 5 — distinct and non-zero.
     */
    uint32_t ma = (uint32_t)(r1 + r2) & 0xFF;
    uint32_t mb = (uint32_t)(r3 / 8) & 0xFF;
    return (3u << 16) | (ma << 8) | mb;
}

void _start(void) {
    g_result = run_tos_tests();
    while (1) {}
}
