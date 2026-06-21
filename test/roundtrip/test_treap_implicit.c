/* test_treap_implicit.c
 * Purpose   : Validate implicit treap (rope-like BST) supporting split/merge
 * Algorithm : Randomised BST keyed by implicit rank.  Nodes carry a priority
 *             (random), size subtree count, and lazy-reverse flag.  Split/merge
 *             maintain heap property on priority, BST property on implicit key.
 *             Used here to build array [1..8], reverse the sub-range [2..5],
 *             then sum all elements.
 * Expected  : Original [1,2,3,4,5,6,7,8]; after reverse [2..5]: [1,5,4,3,2,6,7,8]
 *             sum = 1+5+4+3+2+6+7+8 = 36, n=8, min_val=1
 * g_result  = (n << 16) | (sum_low8 << 8) | min_val
 *           = (8 << 16) | (36 << 8) | 1 = 0x082401
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define TREAP_MAXN 32

typedef struct TNode {
    int val, prio, sz;
    int rev;
    int left, right;   /* indices into pool; 0 = null */
} TNode;

static TNode pool[TREAP_MAXN];
static int   pool_top;

/* Simple LCG for priorities */
static uint32_t lcg_state = 0xDEADBEEFu;
static uint32_t lcg_next(void) {
    lcg_state = lcg_state * 1664525u + 1013904223u;
    return lcg_state;
}

static int new_node(int val) {
    int i = ++pool_top;
    pool[i].val   = val;
    pool[i].prio  = (int)(lcg_next() & 0x7FFFFFFF);
    pool[i].sz    = 1;
    pool[i].rev   = 0;
    pool[i].left  = 0;
    pool[i].right = 0;
    return i;
}

static void push_up(int t) {
    if (!t) return;
    pool[t].sz = 1;
    if (pool[t].left)  pool[t].sz += pool[pool[t].left].sz;
    if (pool[t].right) pool[t].sz += pool[pool[t].right].sz;
}

static void push_down(int t) {
    if (!t || !pool[t].rev) return;
    /* swap children */
    int tmp = pool[t].left;
    pool[t].left  = pool[t].right;
    pool[t].right = tmp;
    /* propagate rev flag */
    if (pool[t].left)  pool[pool[t].left].rev  ^= 1;
    if (pool[t].right) pool[pool[t].right].rev ^= 1;
    pool[t].rev = 0;
}

/* Split t into l (first k nodes) and r (rest) */
static void treap_split(int t, int k, int *l, int *r) {
    if (!t) { *l = 0; *r = 0; return; }
    push_down(t);
    int lsz = pool[t].left ? pool[pool[t].left].sz : 0;
    if (lsz >= k) {
        treap_split(pool[t].left, k, l, &pool[t].left);
        push_up(t);
        *r = t;
    } else {
        treap_split(pool[t].right, k - lsz - 1, &pool[t].right, r);
        push_up(t);
        *l = t;
    }
}

/* Merge two treaps preserving heap on prio */
static int treap_merge(int l, int r) {
    if (!l) return r;
    if (!r) return l;
    push_down(l); push_down(r);
    if (pool[l].prio > pool[r].prio) {
        pool[l].right = treap_merge(pool[l].right, r);
        push_up(l);
        return l;
    } else {
        pool[r].left = treap_merge(l, pool[r].left);
        push_up(r);
        return r;
    }
}

/* Reverse sub-range [ql, qr] (1-indexed) */
static void treap_reverse(int *root, int ql, int qr) {
    int l, m, r2;
    treap_split(*root, ql - 1, &l, &m);
    treap_split(m, qr - ql + 1, &m, &r2);
    pool[m].rev ^= 1;
    *root = treap_merge(treap_merge(l, m), r2);
}

/* In-order traversal to collect values */
static int collect[TREAP_MAXN];
static int collect_top;

static void inorder(int t) {
    if (!t) return;
    push_down(t);
    inorder(pool[t].left);
    collect[collect_top++] = pool[t].val;
    inorder(pool[t].right);
}

void _start(void) {
    pool_top = 0;
    int root = 0;

    /* Build array [1..8] by inserting nodes */
    for (int i = 1; i <= 8; i++) {
        int nd = new_node(i);
        root = treap_merge(root, nd);
    }

    /* Reverse sub-range [2..5] (1-indexed) */
    treap_reverse(&root, 2, 5);

    /* Collect values via in-order traversal */
    collect_top = 0;
    inorder(root);

    int n       = collect_top;   /* should be 8 */
    int sum     = 0;
    int min_val = collect[0];
    for (int i = 0; i < n; i++) {
        sum += collect[i];
        if (collect[i] < min_val) min_val = collect[i];
    }

    /* sum=36, n=8, min_val=1 => 0x082401 */
    g_result = ((uint32_t)n << 16)
             | ((uint32_t)(sum & 0xFF) << 8)
             | (uint32_t)min_val;
    while (1) {}
}
