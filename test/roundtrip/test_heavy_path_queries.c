/*
 * test_heavy_path_queries.c
 * Heavy path decomposition with path queries:
 * Decomposes a rooted tree into heavy chains and answers
 * path sum queries between any two nodes using a flat segment tree
 * layered onto each chain.  Path is split along the heavy-light
 * boundary at each step.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define HPQ_MAXN 16

/* Tree structure */
static int hpq_head[HPQ_MAXN];   /* adjacency list heads */
static int hpq_next[HPQ_MAXN*2];
static int hpq_to[HPQ_MAXN*2];
static int hpq_ecnt;

/* HLD bookkeeping */
static int hpq_par[HPQ_MAXN];
static int hpq_depth[HPQ_MAXN];
static int hpq_sz[HPQ_MAXN];
static int hpq_heavy[HPQ_MAXN];   /* heavy child index, -1 if leaf */
static int hpq_head_chain[HPQ_MAXN]; /* chain head for each node */
static int hpq_pos[HPQ_MAXN];     /* position in flat array */
static int hpq_val[HPQ_MAXN];     /* node values */
static int hpq_flat[HPQ_MAXN];    /* flat array of values in HLD order */
static int hpq_n;
static int hpq_timer;

/* Segment tree on flat array */
static int hpq_seg[HPQ_MAXN * 4];

static void hpq_init(int n) {
    hpq_n = n;
    for (int i = 0; i < n; i++) hpq_head[i] = -1;
    hpq_ecnt = 0;
    hpq_timer = 0;
}

static void hpq_add_edge(int u, int v) {
    hpq_to[hpq_ecnt]   = v;
    hpq_next[hpq_ecnt] = hpq_head[u];
    hpq_head[u]         = hpq_ecnt++;
    hpq_to[hpq_ecnt]   = u;
    hpq_next[hpq_ecnt] = hpq_head[v];
    hpq_head[v]         = hpq_ecnt++;
}

/* DFS1: compute sz, heavy child, parent, depth */
static int dfs1_stk[HPQ_MAXN];
static int dfs1_par[HPQ_MAXN];

static void hpq_dfs1(int root) {
    int top = 0;
    dfs1_stk[top]  = root;
    dfs1_par[top]  = -1;
    hpq_par[root]  = -1;
    hpq_depth[root] = 0;
    while (top >= 0) {
        int u = dfs1_stk[top];
        /* First visit: initialize */
        if (hpq_sz[u] == 0) {
            hpq_sz[u] = 1;
            hpq_heavy[u] = -1;
            for (int e = hpq_head[u]; e != -1; e = hpq_next[e]) {
                int v = hpq_to[e];
                if (v == dfs1_par[top]) continue;
                hpq_par[v]    = u;
                hpq_depth[v]  = hpq_depth[u] + 1;
                top++;
                dfs1_stk[top] = v;
                dfs1_par[top] = u;
            }
        } else {
            /* Post-order: accumulate sz */
            top--;
            int p = hpq_par[u];
            if (p != -1) {
                hpq_sz[p] += hpq_sz[u];
                if (hpq_heavy[p] == -1 || hpq_sz[u] > hpq_sz[hpq_heavy[p]])
                    hpq_heavy[p] = u;
            }
        }
    }
}

/* DFS2: assign chain heads and flat positions */
static int dfs2_stk[HPQ_MAXN];
static int dfs2_chain[HPQ_MAXN];

static void hpq_dfs2(int root) {
    int top = 0;
    dfs2_stk[top]   = root;
    dfs2_chain[top] = root;
    while (top >= 0) {
        int u = dfs2_stk[top];
        int ch = dfs2_chain[top];
        top--;
        hpq_head_chain[u] = ch;
        hpq_pos[u]        = hpq_timer;
        hpq_flat[hpq_timer++] = hpq_val[u];
        /* Push light children first (processed later) */
        for (int e = hpq_head[u]; e != -1; e = hpq_next[e]) {
            int v = hpq_to[e];
            if (v == hpq_par[u] || v == hpq_heavy[u]) continue;
            top++;
            dfs2_stk[top]  = v;
            dfs2_chain[top] = v;
        }
        /* Push heavy child last (processed first = continues chain) */
        if (hpq_heavy[u] != -1) {
            top++;
            dfs2_stk[top]  = hpq_heavy[u];
            dfs2_chain[top] = ch;
        }
    }
}

/* Segment tree: build, query */
static void hpq_seg_build(int node, int l, int r) {
    if (l == r) { hpq_seg[node] = hpq_flat[l]; return; }
    int mid = (l + r) / 2;
    hpq_seg_build(node*2,   l,   mid);
    hpq_seg_build(node*2+1, mid+1, r);
    hpq_seg[node] = hpq_seg[node*2] + hpq_seg[node*2+1];
}

static int hpq_seg_query(int node, int l, int r, int ql, int qr) {
    if (ql > r || qr < l) return 0;
    if (ql <= l && r <= qr) return hpq_seg[node];
    int mid = (l + r) / 2;
    return hpq_seg_query(node*2, l, mid, ql, qr)
         + hpq_seg_query(node*2+1, mid+1, r, ql, qr);
}

/* Path sum from u to v */
static int hpq_path_sum(int u, int v) {
    int ans = 0;
    while (hpq_head_chain[u] != hpq_head_chain[v]) {
        if (hpq_depth[hpq_head_chain[u]] < hpq_depth[hpq_head_chain[v]]) {
            int t = u; u = v; v = t;
        }
        ans += hpq_seg_query(1, 0, hpq_n-1, hpq_pos[hpq_head_chain[u]], hpq_pos[u]);
        u = hpq_par[hpq_head_chain[u]];
    }
    if (hpq_depth[u] > hpq_depth[v]) { int t = u; u = v; v = t; }
    ans += hpq_seg_query(1, 0, hpq_n-1, hpq_pos[u], hpq_pos[v]);
    return ans;
}

static uint32_t run_hpq_tests(void) {
    /*
     * Test 1: Path sum on a 7-node binary tree.
     *       0(1)
     *      / \
     *    1(2) 2(3)
     *   / \   / \
     * 3(4)4(5)5(6)6(7)
     * Node values = index+1.
     * path_sum(3, 6) = val[3]+val[1]+val[0]+val[2]+val[6] = 4+2+1+3+7 = 17
     */
    hpq_init(7);
    for (int i = 0; i < 7; i++) { hpq_sz[i] = 0; hpq_val[i] = i + 1; }
    hpq_add_edge(0,1); hpq_add_edge(0,2);
    hpq_add_edge(1,3); hpq_add_edge(1,4);
    hpq_add_edge(2,5); hpq_add_edge(2,6);
    hpq_dfs1(0);
    hpq_dfs2(0);
    hpq_seg_build(1, 0, 6);
    int sum1 = hpq_path_sum(3, 6); /* expect 17 */

    /*
     * Test 2: Path sum from leaf to root.
     * path_sum(4, 0) = val[4]+val[1]+val[0] = 5+2+1 = 8
     */
    int sum2 = hpq_path_sum(4, 0); /* expect 8 */

    /*
     * Test 3: Path sum single node.
     * path_sum(0, 0) = val[0] = 1
     */
    int sum3 = hpq_path_sum(0, 0); /* expect 1 */

    /*
     * Pack: n_tests=3, metric_a=sum1&0xFF=17=0x11,
     * metric_b=sum2=8=0x08.
     * Bytes: 0x03, 0x11, 0x08 — non-zero, distinct.
     */
    uint32_t metric_a = (uint32_t)(sum1 & 0xFF); /* 17 = 0x11 */
    uint32_t metric_b = (uint32_t)(sum2 & 0xFF); /* 8 = 0x08 */
    (void)sum3;
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_hpq_tests();
    while (1) {}
}
