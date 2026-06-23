/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Heavy-Light Decomposition (HLD) path queries.
 *
 * HLD decomposes a tree into heavy chains so that any root-to-node path
 * crosses O(log n) chains.  Each chain is stored contiguously in a Fenwick
 * tree, enabling O(log^2 n) path-sum queries.
 *
 * Distinctive decompiler idioms:
 *   1. while (chain[u] != chain[v]) — chain-ascent loop (core HLD pattern)
 *   2. if (depth[chain[u]] < depth[chain[v]]) swap(u,v) — deeper chain first
 *   3. pos[v] updates in DFS for the Fenwick linearisation
 *   4. heavy[v] = child with max subtree size (heavy-child selection)
 *   5. Fenwick point-update + prefix-sum for chain range queries
 *
 * Tree (7 nodes, 1-indexed, root=1):
 *   1─2─4
 *     └─5
 *   1─3─6
 *     └─7
 * Subtree sizes: sz[1]=7,sz[2]=3,sz[3]=3,sz[4]=1,sz[5]=1,sz[6]=1,sz[7]=1
 * Heavy children: heavy[1]=2, heavy[2]=4, heavy[3]=6 (first heavy child wins)
 *
 * Initial values: val[i] = i  (1,2,3,4,5,6,7)
 * Path query sum(3→6): nodes on path = {3,6}, sum = 3+6 = 9
 * Path query sum(1→4): nodes on path = {1,2,4}, sum = 1+2+4 = 7
 *
 * g_result = (sum(3→6) << 8) | sum(1→4) = (9 << 8) | 7 = 0x0907 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define HLD_N 8  /* nodes 1..7, index 0 unused */

static int hld_parent[HLD_N];
static int hld_depth[HLD_N];
static int hld_sz[HLD_N];
static int hld_heavy[HLD_N];  /* -1 = leaf */
static int hld_head[HLD_N];   /* head of chain */
static int hld_pos[HLD_N];    /* DFS-order position in Fenwick */
static int hld_fenwick[HLD_N];
static int hld_timer;

/* Adjacency list (static, small tree) */
static int hld_adj[HLD_N][3];
static int hld_deg[HLD_N];

static void hld_add_edge(int u, int v) {
    hld_adj[u][hld_deg[u]++] = v;
    hld_adj[v][hld_deg[v]++] = u;
}

/* DFS to compute sz, heavy, depth, parent */
static void hld_dfs_sz(int v, int p, int d) {
    hld_parent[v] = p;
    hld_depth[v]  = d;
    hld_sz[v]     = 1;
    hld_heavy[v]  = -1;
    int max_sz = 0;
    for (int i = 0; i < hld_deg[v]; i++) {
        int u = hld_adj[v][i];
        if (u == p) continue;
        hld_dfs_sz(u, v, d + 1);
        hld_sz[v] += hld_sz[u];
        if (hld_sz[u] > max_sz) {
            max_sz = hld_sz[u];
            hld_heavy[v] = u;
        }
    }
}

/* DFS to assign chain heads and Fenwick positions */
static void hld_dfs_hld(int v, int head) {
    hld_head[v] = head;
    hld_pos[v]  = ++hld_timer;
    /* first recurse heavy child to keep chain contiguous */
    if (hld_heavy[v] != -1)
        hld_dfs_hld(hld_heavy[v], head);
    for (int i = 0; i < hld_deg[v]; i++) {
        int u = hld_adj[v][i];
        if (u == hld_parent[v] || u == hld_heavy[v]) continue;
        hld_dfs_hld(u, u);  /* light edge: new chain */
    }
}

static void fenwick_update(int i, int val) {
    for (; i < HLD_N; i += i & (-i))
        hld_fenwick[i] += val;
}

static int fenwick_query(int i) {
    int s = 0;
    for (; i > 0; i -= i & (-i))
        s += hld_fenwick[i];
    return s;
}

static int fenwick_range(int l, int r) {
    return fenwick_query(r) - fenwick_query(l - 1);
}

/* Path sum query using chain ascent */
static int hld_path_sum(int u, int v) {
    int ans = 0;
    while (hld_head[u] != hld_head[v]) {
        /* always ascend the deeper chain */
        if (hld_depth[hld_head[u]] < hld_depth[hld_head[v]]) {
            int t = u; u = v; v = t;
        }
        ans += fenwick_range(hld_pos[hld_head[u]], hld_pos[u]);
        u = hld_parent[hld_head[u]];
    }
    /* same chain: query the segment between u and v */
    if (hld_depth[u] > hld_depth[v]) { int t = u; u = v; v = t; }
    ans += fenwick_range(hld_pos[u], hld_pos[v]);
    return ans;
}

void test_hld(void)
{
    /* Build tree: 1-2, 1-3, 2-4, 2-5, 3-6, 3-7 */
    hld_add_edge(1, 2); hld_add_edge(1, 3);
    hld_add_edge(2, 4); hld_add_edge(2, 5);
    hld_add_edge(3, 6); hld_add_edge(3, 7);

    hld_dfs_sz(1, 0, 0);
    hld_timer = 0;
    hld_dfs_hld(1, 1);

    /* Load node values into Fenwick (val[i] = i) */
    for (int i = 1; i <= 7; i++)
        fenwick_update(hld_pos[i], i);

    int q1 = hld_path_sum(3, 6);  /* 3+6 = 9 */
    int q2 = hld_path_sum(1, 4);  /* 1+2+4 = 7 */

    g_result = ((uint32_t)q1 << 8) | ((uint32_t)q2 & 0xFF);  /* 0x0907 */
}

__attribute__((noreturn)) void _start(void)
{
    test_hld();
    for (;;);
}
