/* test_splay_tree.c
 * Purpose   : Validate a splay tree supporting insert, find, and in-order
 *             traversal.
 * Algorithm : Zig, zig-zig, and zig-zag rotations bring the target node to
 *             the root.  Access pattern creates a working-set property.
 * Keys      : insert {5,3,8,1,4,7,9,2,6}, then splay-access 4 and 7 twice
 * Metrics   :
 *   n_tests  = 9  (keys inserted)
 *   metric_a = in-order rank of root after final splay(7) — expect 6 (0-based)
 *   metric_b = number of successful finds — expect 4
 * g_result  = (9<<16)|(6<<8)|4 = 0x090604
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define SPLAY_MAXN 32

typedef struct SNode {
    int key;
    int ch[2];   /* ch[0]=left, ch[1]=right */
    int parent;
} SNode;

static SNode splay_pool[SPLAY_MAXN];
static int   splay_root;
static int   splay_cnt;

static void splay_init(void) {
    splay_root = -1;
    splay_cnt  = 0;
}

static int splay_new_node(int key) {
    int id = splay_cnt++;
    splay_pool[id].key    = key;
    splay_pool[id].ch[0]  = -1;
    splay_pool[id].ch[1]  = -1;
    splay_pool[id].parent = -1;
    return id;
}

/* Set p as parent of c (if c valid) */
static void splay_setparent(int c, int p) {
    if (c != -1) splay_pool[c].parent = p;
}

/* Rotate node x up one level */
static void splay_rotate(int x) {
    int p  = splay_pool[x].parent;
    int g  = splay_pool[p].parent;
    int dir = (splay_pool[p].ch[1] == x) ? 1 : 0;
    int opp = 1 - dir;

    /* move x's inner child to p */
    int inner = splay_pool[x].ch[opp];
    splay_pool[p].ch[dir] = inner;
    splay_setparent(inner, p);

    /* x takes p's place */
    splay_pool[x].ch[opp] = p;
    splay_pool[p].parent = x;

    /* link x to g */
    splay_pool[x].parent = g;
    if (g != -1) {
        if (splay_pool[g].ch[0] == p) splay_pool[g].ch[0] = x;
        else if (splay_pool[g].ch[1] == p) splay_pool[g].ch[1] = x;
    }
}

/* Splay node x to root */
static void splay_splay(int x) {
    while (splay_pool[x].parent != -1) {
        int p = splay_pool[x].parent;
        int g = splay_pool[p].parent;
        if (g != -1) {
            /* zig-zig or zig-zag */
            int xdir = (splay_pool[p].ch[1] == x);
            int pdir = (splay_pool[g].ch[1] == p);
            if (xdir == pdir)
                splay_rotate(p);  /* zig-zig: rotate parent first */
            else
                splay_rotate(x);  /* zig-zag: rotate x first */
        }
        splay_rotate(x);
    }
    splay_root = x;
}

static void splay_insert(int key) {
    if (splay_root == -1) {
        splay_root = splay_new_node(key);
        return;
    }
    int cur = splay_root, par = -1;
    while (cur != -1) {
        par = cur;
        if (key < splay_pool[cur].key)      cur = splay_pool[cur].ch[0];
        else if (key > splay_pool[cur].key) cur = splay_pool[cur].ch[1];
        else return; /* duplicate */
    }
    int nd = splay_new_node(key);
    splay_pool[nd].parent = par;
    if (key < splay_pool[par].key) splay_pool[par].ch[0] = nd;
    else                            splay_pool[par].ch[1] = nd;
    splay_splay(nd);
}

/* Find key, splay it to root if found.  Returns 1 on success. */
static int splay_find(int key) {
    int cur = splay_root;
    while (cur != -1) {
        if (key == splay_pool[cur].key) { splay_splay(cur); return 1; }
        else if (key < splay_pool[cur].key) cur = splay_pool[cur].ch[0];
        else                                cur = splay_pool[cur].ch[1];
    }
    return 0;
}

/* In-order rank of root (0-based count of nodes with smaller key) */
static int splay_root_rank(void) {
    int rank = 0;
    int cur = splay_pool[splay_root].ch[0];
    /* count nodes in left subtree via traversal */
    int stack[SPLAY_MAXN], sp = 0;
    while (cur != -1 || sp > 0) {
        while (cur != -1) { stack[sp++] = cur; cur = splay_pool[cur].ch[0]; }
        cur = stack[--sp];
        rank++;
        cur = splay_pool[cur].ch[1];
    }
    return rank;
}

void _start(void) {
    splay_init();

    int keys[] = {5, 3, 8, 1, 4, 7, 9, 2, 6};
    for (int i = 0; i < 9; i++) splay_insert(keys[i]);

    int found = 0;
    found += splay_find(4);
    found += splay_find(7);
    found += splay_find(4);
    found += splay_find(7);  /* access 7 last — it becomes root */

    int rank = splay_root_rank();   /* expect 6 (keys 1,2,3,4,5,6 are smaller) */

    uint32_t n_tests  = 9;
    uint32_t metric_a = (uint32_t)(rank  & 0xFF);   /* 6 */
    uint32_t metric_b = (uint32_t)(found & 0xFF);   /* 4 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    /* expected: 0x090604 */
    while (1) {}
}
