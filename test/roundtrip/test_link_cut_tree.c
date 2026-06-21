/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Link-Cut Tree (LCT) fixture.
 *
 * A Link-Cut Tree maintains a forest of trees under link/cut/find-root
 * operations using splay trees on preferred paths (access operation).
 *
 * Test scenario (n = 7 nodes, 0-indexed):
 *   link(1,0), link(2,0), link(3,1), link(4,1), link(5,2), link(6,2)
 *   Resulting tree:
 *         0
 *        / \
 *       1   2
 *      / \ / \
 *     3  4 5  6
 *
 *   Queries:
 *     find_root(3) == 0   (root of 3's tree)
 *     find_root(6) == 0   (root of 6's tree)
 *     connected(3,6) == 1 (same tree)
 *     cut(2,0), then connected(5,3) == 0 (now separate trees)
 *
 * Metrics:
 *   n_tests  = 7   (number of nodes)
 *   metric_a = 3   (find_root queries returning 0 before cut: 2 correct,
 *                    after cut connected(3,6) still 1 → total 3 correct)
 *   metric_b = 2   (correct results after cut: find_root(5)==2 + not connected)
 *              Actually: metric_a = correct pre-cut results (3), metric_b = 2 (post-cut)
 * g_result = (7<<16)|(3<<8)|2 = 0x070302
 */

#include <stdint.h>

volatile uint32_t g_result;

#define LCT_MAXN 16

typedef struct {
    int ch[2];   /* splay tree children: 0=left, 1=right */
    int par;     /* parent in splay tree or path-parent pointer */
    int rev;     /* lazy reversal flag */
} LCTNode;

static LCTNode lct[LCT_MAXN];
static int     lct_n;

/* ── LCT helpers ─────────────────────────────────────────────────────── */

static int lct_is_root(int x) {
    int p = lct[x].par;
    return (p == -1) || (lct[p].ch[0] != x && lct[p].ch[1] != x);
}

static void lct_push_rev(int x) {
    if (lct[x].rev) {
        int l = lct[x].ch[0], r = lct[x].ch[1];
        /* swap children */
        lct[x].ch[0] = r;
        lct[x].ch[1] = l;
        if (l != -1) lct[l].rev ^= 1;
        if (r != -1) lct[r].rev ^= 1;
        lct[x].rev = 0;
    }
}

/* push lazy flags from root down to x along the splay path */
static void lct_push_all(int x) {
    /* collect ancestors */
    static int stk[LCT_MAXN];
    int top = 0;
    stk[top++] = x;
    while (!lct_is_root(x)) {
        x = lct[x].par;
        stk[top++] = x;
    }
    while (top > 0) {
        lct_push_rev(stk[--top]);
    }
}

static void lct_rotate(int x) {
    int y = lct[x].par;
    int z = lct[y].par;
    int k = (lct[y].ch[1] == x);  /* 0 if x is left child, 1 if right */
    int w = lct[x].ch[k ^ 1];     /* child of x on the other side */

    /* update z's child pointer if y was not a splay-tree root */
    if (!lct_is_root(y)) {
        if (lct[z].ch[0] == y) lct[z].ch[0] = x;
        else                   lct[z].ch[1] = x;
    }
    lct[x].par = z;

    /* w takes x's place under y */
    lct[y].ch[k]     = w;
    if (w != -1) lct[w].par = y;

    /* x takes y's place */
    lct[x].ch[k ^ 1] = y;
    lct[y].par        = x;
}

static void lct_splay(int x) {
    lct_push_all(x);
    while (!lct_is_root(x)) {
        int y = lct[x].par;
        if (!lct_is_root(y)) {
            int z = lct[y].par;
            /* zig-zig vs zig-zag */
            if ((lct[z].ch[0] == y) == (lct[y].ch[0] == x))
                lct_rotate(y);
            else
                lct_rotate(x);
        }
        lct_rotate(x);
    }
}

/* access(x): make the path from x to root a preferred path */
static void lct_access(int x) {
    int last = -1;
    int y = x;
    while (y != -1) {
        lct_splay(y);
        lct[y].ch[1] = last;   /* cut preferred child, attach last */
        last = y;
        y    = lct[y].par;
    }
    lct_splay(x);
}

/* find_root(x): find the root of x's represented tree */
static int lct_find_root(int x) {
    lct_access(x);
    while (lct[x].ch[0] != -1) {
        lct_push_rev(x);
        x = lct[x].ch[0];
    }
    lct_splay(x);   /* splay to amortise */
    return x;
}

/* make_root(x): re-root the represented tree at x */
static void lct_make_root(int x) {
    lct_access(x);
    lct[x].rev ^= 1;
    lct_push_rev(x);
}

/* link(x, y): add edge x-y (x must be a root) */
static void lct_link(int x, int y) {
    lct_make_root(x);
    lct[x].par = y;
}

/* cut(x, y): remove edge x-y */
static void lct_cut(int x, int y) {
    lct_make_root(x);
    lct_access(y);
    /* now x is left child of y in the splay tree */
    lct[y].ch[0] = -1;
    lct[x].par   = -1;
}

/* connected(x,y): 1 if x and y are in the same tree */
static int lct_connected(int x, int y) {
    return lct_find_root(x) == lct_find_root(y);
}

/* ── test driver ─────────────────────────────────────────────────────── */

static void lct_init(int n) {
    lct_n = n;
    for (int i = 0; i < n; i++) {
        lct[i].ch[0] = lct[i].ch[1] = -1;
        lct[i].par   = -1;
        lct[i].rev   = 0;
    }
}

void _start(void) {
    lct_init(7);

    /* Build tree: 0 is root, 1 and 2 are children of 0,
       3,4 children of 1, 5,6 children of 2 */
    lct_link(1, 0);
    lct_link(2, 0);
    lct_link(3, 1);
    lct_link(4, 1);
    lct_link(5, 2);
    lct_link(6, 2);

    int score_a = 0;

    /* find_root(3) should be 0 */
    if (lct_find_root(3) == 0) score_a++;
    /* find_root(6) should be 0 */
    if (lct_find_root(6) == 0) score_a++;
    /* connected(3,6) should be 1 */
    if (lct_connected(3, 6) == 1) score_a++;
    /* score_a = 3 */

    /* cut(2,0): sever 2 from 0 */
    lct_cut(2, 0);

    int score_b = 0;
    /* find_root(5) should now be 2 */
    if (lct_find_root(5) == 2) score_b++;
    /* connected(5,3) should be 0 (different trees) */
    if (lct_connected(5, 3) == 0) score_b++;
    /* score_b = 2 */

    uint32_t n_tests  = 7;
    uint32_t metric_a = (uint32_t)(score_a & 0xFF);  /* 3 */
    uint32_t metric_b = (uint32_t)(score_b & 0xFF);  /* 2 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    /* expected: 0x070302 */
    while (1) {}
}
