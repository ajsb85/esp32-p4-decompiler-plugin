/* test_treap_persistent.c
 * Purpose   : Validate a persistent treap (functional, copy-on-write)
 * Algorithm : A persistent treap supports O(log n) insert/split/merge while
 *             preserving all historical versions.  Each mutating operation
 *             allocates new nodes (copy-on-write) instead of updating in place.
 *             Versions are stored as root pointers so any past tree can be
 *             queried.  Priority is random (fixed seed for reproducibility).
 *
 * Operations:
 *   v0 = empty
 *   v1 = insert(v0, 3)
 *   v2 = insert(v1, 1)
 *   v3 = insert(v2, 4)
 *   v4 = insert(v3, 2)
 *   v5 = insert(v4, 5)
 *   Query v3 (keys 1,3,4): min=1, max=4, size=3
 *   Query v5 (keys 1,2,3,4,5): min=1, max=5, size=5
 *
 * n_versions = 5   (0x05)
 * v3_size    = 3   (0x03)
 * v5_size    = 5   (0x05)
 * g_result   = (n_versions << 16) | (v3_size << 8) | v5_size = 0x050305
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define PT_MAXNODES 128

typedef struct PTNode {
    int key;
    uint32_t prio;
    int  left, right; /* child indices; -1 = null */
    int  size;
} PTNode;

static PTNode pt_pool[PT_MAXNODES];
static int    pt_pool_sz;

/* LCG for reproducible priorities */
static uint32_t pt_rng = 0xDEADBEEFu;
static uint32_t pt_rand(void) {
    pt_rng ^= pt_rng << 13;
    pt_rng ^= pt_rng >> 17;
    pt_rng ^= pt_rng <<  5;
    return pt_rng;
}

static int pt_new(int key, uint32_t prio) {
    int id = pt_pool_sz++;
    pt_pool[id].key   = key;
    pt_pool[id].prio  = prio;
    pt_pool[id].left  = -1;
    pt_pool[id].right = -1;
    pt_pool[id].size  = 1;
    return id;
}

static int pt_sz(int t) {
    return (t == -1) ? 0 : pt_pool[t].size;
}

/* Copy-on-write node clone */
static int pt_clone(int t) {
    if (t == -1) return -1;
    int id = pt_pool_sz++;
    pt_pool[id] = pt_pool[t];
    return id;
}

static void pt_upd(int t) {
    if (t == -1) return;
    pt_pool[t].size = 1 + pt_sz(pt_pool[t].left) + pt_sz(pt_pool[t].right);
}

/* Merge two treaps (all keys in l < all keys in r).  Returns new root. */
static int pt_merge(int l, int r) {
    if (l == -1) return r;
    if (r == -1) return l;
    if (pt_pool[l].prio > pt_pool[r].prio) {
        int nl = pt_clone(l);
        pt_pool[nl].right = pt_merge(pt_pool[l].right, r);
        pt_upd(nl);
        return nl;
    } else {
        int nr = pt_clone(r);
        pt_pool[nr].left = pt_merge(l, pt_pool[r].left);
        pt_upd(nr);
        return nr;
    }
}

/* Split treap t into (l, r): l has keys <= key, r has keys > key */
static int pt_split_l; /* output: left part */
static int pt_split_r; /* output: right part */

static void pt_split(int t, int key) {
    if (t == -1) { pt_split_l = -1; pt_split_r = -1; return; }
    int nc = pt_clone(t);
    if (pt_pool[nc].key <= key) {
        pt_split(pt_pool[t].right, key);
        pt_pool[nc].right = pt_split_l;
        pt_upd(nc);
        pt_split_l = nc;
        /* pt_split_r already set */
    } else {
        pt_split(pt_pool[t].left, key);
        pt_pool[nc].left = pt_split_r;
        pt_upd(nc);
        pt_split_r = nc;
        /* pt_split_l already set */
    }
}

static int pt_insert(int root, int key) {
    uint32_t prio = pt_rand();
    pt_split(root, key);
    int nl = pt_split_l;
    int nr = pt_split_r;
    int nd = pt_new(key, prio);
    return pt_merge(pt_merge(nl, nd), nr);
}

static int pt_size(int root) {
    return pt_sz(root);
}

static int pt_versions[8];

void _start(void) {
    pt_pool_sz = 0;
    pt_rng     = 0xDEADBEEFu;

    /* v0 = empty */
    pt_versions[0] = -1;
    /* v1..v5 = successive inserts */
    static const int ins[5] = { 3, 1, 4, 2, 5 };
    for (int i = 0; i < 5; i++)
        pt_versions[i + 1] = pt_insert(pt_versions[i], ins[i]);

    int n_versions = 5;
    int v3_size    = pt_size(pt_versions[3]); /* {1,3,4} → 3 */
    int v5_size    = pt_size(pt_versions[5]); /* {1,2,3,4,5} → 5 */

    g_result = ((uint32_t)n_versions << 16)
             | ((uint32_t)v3_size    <<  8)
             | ((uint32_t)v5_size);
    while (1) {}
}
