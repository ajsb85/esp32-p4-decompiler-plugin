/* test_virtual_tree.c
 * Purpose   : Validate virtual tree (auxiliary tree) construction over a rooted
 *             tree for a query set of key nodes.
 * Algorithm : Given a rooted tree with n nodes and a set S of k query nodes,
 *             build the "virtual tree" (auxiliary tree) containing only:
 *               - All nodes in S
 *               - All LCA pairs of consecutive nodes in S (sorted by DFS order)
 *               - The root (if not already included)
 *             Steps:
 *               1. Euler-tour DFS to assign in-time (tin) and parent[].
 *               2. Sort S by tin.
 *               3. Sweep with a stack; for each node v in sorted S:
 *                    l = LCA(stack.top, v); if l != stack.top: add edge l→stack.top
 *               4. Count edges in virtual tree.
 *             Characteristic idioms: tin-sorted query set, LCA via binary lifting,
 *             monotone stack of ancestors, `if (tin[lca] < tin[stk.top]) pop`.
 * Input     : 7-node tree (1-indexed, root=1):
 *               1→{2,3}, 2→{4,5}, 3→{6,7}
 *             Query set S = {4, 5, 6} (leaves from different subtrees).
 *             Virtual tree nodes: {1, 2, 3, 4, 5, 6} (LCA(4,5)=2, LCA(2,6)=1, LCA(1,6)... need 3).
 *             Edges in virtual tree: 1→2, 1→3, 2→4, 2→5, 3→6  → 5 edges.
 * g_result  = (n_nodes << 16) | (vt_nodes << 8) | vt_edges
 *           = (7 << 16) | (6 << 8) | 5  => 0x070605
 */
#include <stdint.h>

volatile uint32_t g_result;

#define VT_N    8   /* nodes 1..7, index 0 unused */
#define VT_LOG  3   /* ceil(log2(7)) */

static int vt_parent[VT_N];
static int vt_tin[VT_N];
static int vt_depth[VT_N];
static int vt_up[VT_LOG][VT_N]; /* binary lifting: vt_up[k][v] = 2^k-th ancestor */
static int vt_timer;

/* Adjacency list for original tree (children only, since rooted) */
static int vt_ch[VT_N][VT_N]; /* vt_ch[u] = list of children */
static int vt_ch_cnt[VT_N];

static void vt_add_child(int parent, int child) {
    vt_ch[parent][vt_ch_cnt[parent]++] = child;
}

/* Iterative DFS to assign tin, depth, parent */
static int vt_dfs_stk[VT_N];
static int vt_dfs_idx[VT_N]; /* next child index to visit */

static void vt_dfs(int root) {
    int top = 0;
    vt_dfs_stk[top] = root;
    vt_dfs_idx[top] = 0;
    vt_depth[root] = 0;
    vt_parent[root] = 0;
    vt_tin[root] = ++vt_timer;

    while (top >= 0) {
        int u = vt_dfs_stk[top];
        if (vt_dfs_idx[top] < vt_ch_cnt[u]) {
            int v = vt_ch[u][vt_dfs_idx[top]++];
            vt_parent[v] = u;
            vt_depth[v]  = vt_depth[u] + 1;
            vt_tin[v]    = ++vt_timer;
            top++;
            vt_dfs_stk[top] = v;
            vt_dfs_idx[top] = 0;
        } else {
            top--;
        }
    }
}

/* Build binary lifting table */
static void vt_build_lift(int n) {
    for (int v = 1; v <= n; v++) vt_up[0][v] = vt_parent[v];
    vt_up[0][1] = 1; /* root's parent is itself for LCA purposes */
    for (int k = 1; k < VT_LOG; k++)
        for (int v = 1; v <= n; v++)
            vt_up[k][v] = vt_up[k-1][vt_up[k-1][v]];
}

/* LCA via binary lifting */
static int vt_lca(int u, int v) {
    if (vt_depth[u] < vt_depth[v]) { int t = u; u = v; v = t; }
    int diff = vt_depth[u] - vt_depth[v];
    for (int k = 0; k < VT_LOG; k++)
        if ((diff >> k) & 1) u = vt_up[k][u];
    if (u == v) return u;
    for (int k = VT_LOG - 1; k >= 0; k--)
        if (vt_up[k][u] != vt_up[k][v]) { u = vt_up[k][u]; v = vt_up[k][v]; }
    return vt_up[0][u];
}

/* Sort small array of nodes by tin (insertion sort) */
static void vt_sort_by_tin(int *arr, int sz) {
    for (int i = 1; i < sz; i++) {
        int key = arr[i];
        int j = i - 1;
        while (j >= 0 && vt_tin[arr[j]] > vt_tin[key]) { arr[j+1] = arr[j]; j--; }
        arr[j+1] = key;
    }
}

void test_virtual_tree(void) {
    /* Build tree: 1→{2,3}, 2→{4,5}, 3→{6,7} */
    vt_add_child(1, 2); vt_add_child(1, 3);
    vt_add_child(2, 4); vt_add_child(2, 5);
    vt_add_child(3, 6); vt_add_child(3, 7);

    vt_dfs(1);
    vt_build_lift(7);

    /* Query set S = {4, 5, 6} sorted by tin */
    int S[3] = {4, 5, 6};
    vt_sort_by_tin(S, 3);

    /* Build virtual tree with monotone-stack algorithm */
    int stk[VT_N];
    int stk_top = 0;
    stk[stk_top++] = 1; /* push root */

    /* Track edges of virtual tree */
    int edge_from[VT_N * 2];
    int edge_to[VT_N * 2];
    int edge_cnt = 0;

    /* Track which nodes appear */
    int in_vt[VT_N];
    for (int i = 0; i < VT_N; i++) in_vt[i] = 0;
    in_vt[1] = 1;

    for (int i = 0; i < 3; i++) {
        int v = S[i];
        int l = vt_lca(stk[stk_top - 1], v);

        if (l != stk[stk_top - 1]) {
            /* Pop nodes that are deeper than l, adding edges */
            while (stk_top > 1 && vt_depth[stk[stk_top - 2]] >= vt_depth[l]) {
                edge_from[edge_cnt] = stk[stk_top - 2];
                edge_to[edge_cnt]   = stk[stk_top - 1];
                edge_cnt++;
                stk_top--;
            }
            /* Add edge from l to current top */
            edge_from[edge_cnt] = l;
            edge_to[edge_cnt]   = stk[stk_top - 1];
            edge_cnt++;
            stk_top--;
            if (!in_vt[l]) { in_vt[l] = 1; }
            stk[stk_top++] = l;
        }
        in_vt[v] = 1;
        stk[stk_top++] = v;
    }
    /* Drain remaining stack */
    while (stk_top > 1) {
        edge_from[edge_cnt] = stk[stk_top - 2];
        edge_to[edge_cnt]   = stk[stk_top - 1];
        edge_cnt++;
        stk_top--;
    }

    /* Count virtual tree nodes */
    int vt_nodes = 0;
    for (int i = 1; i < VT_N; i++) if (in_vt[i]) vt_nodes++;

    (void)edge_from; (void)edge_to;

    /* n_nodes=7, vt_nodes=6, vt_edges=5 */
    g_result = ((uint32_t)7          << 16)
             | ((uint32_t)vt_nodes   <<  8)
             | (uint32_t)edge_cnt;
    while (1) {}
}

__attribute__((noreturn)) void _start(void) {
    test_virtual_tree();
    for (;;);
}
