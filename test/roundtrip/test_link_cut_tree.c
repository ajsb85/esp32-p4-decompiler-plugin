/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Link-Cut Tree (splay-based dynamic trees).
 *
 * A Link-Cut Tree maintains a forest of trees supporting link/cut/path queries
 * in O(log n) amortized.  Implemented via splay trees on preferred paths.
 *
 * Distinctive decompiler idioms:
 *   1. is_root(v) = !path_parent(v) && !left/right of parent — root test
 *   2. splay(v) — bring v to top of its auxiliary splay tree
 *   3. access(v) — chain of splays that creates preferred path to root
 *   4. link(u,v) — access(u); make u a child of v (path_parent[u] = v)
 *   5. cut(v) — access(v); splay to root; detach left child
 *
 * Operations tested:
 *   - Build path: 1-2-3-4-5 via link()
 *   - path_sum(1,5) = 1+2+3+4+5 = 15
 *   - cut(3)  — splits into {1,2,3} and {4,5}
 *   - path_sum(1,2) = 3
 *
 * g_result = (path_sum_1_to_5 << 16) | (path_sum_1_to_2 << 8) | n_nodes
 *          = (15 << 16) | (3 << 8) | 5
 *          = 0x0F0305 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LCT_N 8

typedef struct {
    int ch[2];   /* splay tree children: 0=left, 1=right */
    int par;     /* parent in splay tree (or path-parent if is_root) */
    int val;     /* node value */
    int sum;     /* subtree sum */
    int rev;     /* lazy reverse flag */
} LCTNode;

static LCTNode lct[LCT_N];

static void lct_push_up(int v) {
    lct[v].sum = lct[v].val;
    if (lct[v].ch[0]) lct[v].sum += lct[lct[v].ch[0]].sum;
    if (lct[v].ch[1]) lct[v].sum += lct[lct[v].ch[1]].sum;
}

static int lct_is_root(int v) {
    int p = lct[v].par;
    return p == 0 || (lct[p].ch[0] != v && lct[p].ch[1] != v);
}

static void lct_rotate(int v) {
    int p = lct[v].par, g = lct[p].par;
    int d = (lct[p].ch[1] == v);
    int c = lct[v].ch[d ^ 1];

    if (!lct_is_root(p)) lct[g].ch[lct[g].ch[1] == p] = v;
    lct[v].ch[d ^ 1] = p;
    lct[p].ch[d]     = c;
    if (c) lct[c].par = p;
    lct[p].par = v;
    lct[v].par = g;
    lct_push_up(p);
    lct_push_up(v);
}

static void lct_splay(int v) {
    while (!lct_is_root(v)) {
        int p = lct[v].par;
        if (!lct_is_root(p)) {
            int g = lct[p].par;
            int dp = (lct[g].ch[1] == p), dv = (lct[p].ch[1] == v);
            if (dp == dv) lct_rotate(p); else lct_rotate(v);
        }
        lct_rotate(v);
    }
}

static void lct_access(int v) {
    int last = 0;
    for (int u = v; u; u = lct[u].par) {
        lct_splay(u);
        lct[u].ch[1] = last;
        lct_push_up(u);
        last = u;
    }
    lct_splay(v);
}

static void lct_make_root(int v) {
    lct_access(v);
    /* for simplicity without lazy rev: just access — works for path queries
     * in a tree where we query path sums without needing re-rooting */
}

static void lct_link(int u, int v) {
    lct_access(u);
    lct[u].par = v;
}

static void lct_cut(int v) {
    /* Cut v from its parent by removing left child after access */
    lct_access(v);
    if (lct[v].ch[0]) {
        lct[lct[v].ch[0]].par = 0;
        lct[v].ch[0] = 0;
        lct_push_up(v);
    }
}

/* Path sum from fixed root (node 1) to v: access(v) creates preferred path
 * root→v; lct[v].sum after access equals the sum of all nodes on that path. */
static int lct_path_to_root(int v) {
    lct_access(v);
    return lct[v].sum;
}

void test_link_cut_tree(void)
{
    int n = 5;
    /* Init nodes 1..5 with val=i */
    for (int i = 1; i <= n; i++) {
        lct[i].ch[0] = lct[i].ch[1] = lct[i].par = 0;
        lct[i].val = i;
        lct[i].sum = i;
        lct[i].rev = 0;
    }

    /* Link to form chain 1-2-3-4-5 */
    lct_link(2, 1);
    lct_link(3, 2);
    lct_link(4, 3);
    lct_link(5, 4);

    /* Path sum root(1)→5 on full chain = 1+2+3+4+5 = 15 */
    int s1 = lct_path_to_root(5);

    /* Cut node 3 (removes the edge above 3, splitting into {1,2} and {3,4,5}) */
    lct_cut(3);

    /* Path sum root(1)→2 = 1+2 = 3 */
    int s2 = lct_path_to_root(2);

    g_result = ((uint32_t)(s1 & 0xFF) << 16)
             | ((uint32_t)(s2 & 0xFF) <<  8)
             | ((uint32_t)n);
}

__attribute__((noreturn)) void _start(void)
{
    test_link_cut_tree();
    for (;;);
}
