/*
 * test_maximum_closure.c
 * Maximum Weight Closure of a directed graph via min-cut / max-flow.
 * Algorithm: A closure of a directed graph G=(V,E) is a subset C of V such
 *   that for every edge (u,v) in E with u in C, v is also in C.  When nodes
 *   have weights (positive or negative), the maximum weight closure maximizes
 *   the total weight of the selected subset.
 *   Reduction to min-cut:
 *     - Source s connects to every node with positive weight w, capacity w.
 *     - Every node with negative weight connects to sink t, capacity |w|.
 *     - Original edges have capacity infinity.
 *     - Max weight closure = sum of positive weights - min-cut(s,t).
 *   Min-cut computed by Dinic's BFS-level-graph + blocking-flow algorithm.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MC_MAXV  32
#define MC_MAXE  256   /* each undirected edge stored as 2 directed + 2 reverse */

static int mc_nv;     /* total nodes including s and t */
static int mc_head[MC_MAXV];
static int mc_to[MC_MAXE];
static int mc_cap[MC_MAXE];
static int mc_nxt[MC_MAXE];
static int mc_ecnt;

static int mc_level[MC_MAXV];
static int mc_iter[MC_MAXV];  /* current edge pointer for Dinic blocking flow */

static void mc_reset(int nv) {
    mc_nv   = nv;
    mc_ecnt = 0;
    for (int i = 0; i < nv; i++) mc_head[i] = -1;
}

/* Add directed edge u->v with capacity c, and its reverse with cap 0 */
static void mc_add_edge(int u, int v, int c) {
    mc_to[mc_ecnt]  = v;
    mc_cap[mc_ecnt] = c;
    mc_nxt[mc_ecnt] = mc_head[u];
    mc_head[u]      = mc_ecnt++;

    mc_to[mc_ecnt]  = u;
    mc_cap[mc_ecnt] = 0;
    mc_nxt[mc_ecnt] = mc_head[v];
    mc_head[v]      = mc_ecnt++;
}

/* BFS to build level graph */
static int mc_bfs_queue[MC_MAXV];

static int mc_bfs(int s, int t) {
    for (int i = 0; i < mc_nv; i++) mc_level[i] = -1;
    mc_level[s] = 0;
    int head = 0, tail = 0;
    mc_bfs_queue[tail++] = s;
    while (head < tail) {
        int u = mc_bfs_queue[head++];
        for (int e = mc_head[u]; e != -1; e = mc_nxt[e]) {
            int v = mc_to[e];
            if (mc_cap[e] > 0 && mc_level[v] == -1) {
                mc_level[v] = mc_level[u] + 1;
                mc_bfs_queue[tail++] = v;
            }
        }
    }
    return mc_level[t] != -1;
}

static int mc_dfs(int u, int t, int pushed) {
    if (u == t) return pushed;
    for (; mc_iter[u] != -1; mc_iter[u] = mc_nxt[mc_iter[u]]) {
        int e = mc_iter[u];
        int v = mc_to[e];
        if (mc_cap[e] <= 0 || mc_level[v] != mc_level[u] + 1) continue;
        int d = mc_dfs(v, t, (pushed < mc_cap[e]) ? pushed : mc_cap[e]);
        if (d > 0) {
            mc_cap[e]     -= d;
            mc_cap[e ^ 1] += d;
            return d;
        }
        mc_level[v] = -1;
    }
    return 0;
}

static int mc_maxflow(int s, int t) {
    int flow = 0;
    while (mc_bfs(s, t)) {
        for (int i = 0; i < mc_nv; i++) mc_iter[i] = mc_head[i];
        int f;
        while ((f = mc_dfs(s, t, 0x7fffffff)) > 0) flow += f;
    }
    return flow;
}

#define MC_INF 0x3fffffff

/*
 * Compute max weight closure for a set of nodes with given weights and edges.
 * nodes: array of node weights (positive or negative)
 * edges: array of (from, to) pairs, 0-indexed into nodes array
 * n: number of nodes, m: number of edges
 * Returns max weight closure value.
 */
static int mc_solve(const int *weights, int n,
                    const int (*edges)[2], int m) {
    int s = n, t = n + 1;  /* source and sink */
    mc_reset(n + 2);

    int pos_sum = 0;
    for (int i = 0; i < n; i++) {
        if (weights[i] > 0) {
            mc_add_edge(s, i, weights[i]);
            pos_sum += weights[i];
        } else if (weights[i] < 0) {
            mc_add_edge(i, t, -weights[i]);
        }
    }
    for (int i = 0; i < m; i++) {
        mc_add_edge(edges[i][0], edges[i][1], MC_INF);
    }
    return pos_sum - mc_maxflow(s, t);
}

static uint32_t run_mc_tests(void) {
    int r1, r2, r3;

    /*
     * Test 1: Classic example.
     *   Nodes: 0(+9), 1(+7), 2(-4), 3(-3), 4(+5)
     *   Edges: 0->2, 0->3, 1->3, 1->4
     *   Optimal closure: {0,1,2,3,4} has weight 9+7-4-3+5=14
     *   But constraint: taking 0 requires 2 and 3; taking 1 requires 3 and 4.
     *   Best: take {0,1,2,3,4} = 14, or {1,3,4}=7-3+5=9, or {0,1,2,3,4}=14
     *   Min-cut check: taking all = 14 (possible since all constraints met).
     */
    {
        int w[5] = {9, 7, -4, -3, 5};
        int e[4][2] = {{0,2},{0,3},{1,3},{1,4}};
        r1 = mc_solve(w, 5, e, 4);  /* expect 14 */
    }

    /*
     * Test 2: Forced negative dependency.
     *   Nodes: 0(+3), 1(-5)
     *   Edges: 0->1
     *   If we take 0, we must take 1: 3-5=-2 < 0, so best is empty set = 0.
     */
    {
        int w[2] = {3, -5};
        int e[1][2] = {{0,1}};
        r2 = mc_solve(w, 2, e, 1);  /* expect 0 */
    }

    /*
     * Test 3: Chain with net positive.
     *   Nodes: 0(+10), 1(-2), 2(-3), 3(+8)
     *   Edges: 0->1, 0->2, 3->2
     *   Taking {0,1,2}: 10-2-3=5. Taking {0,1,2,3}: 10-2-3+8=13. Best=13.
     */
    {
        int w[4] = {10, -2, -3, 8};
        int e[3][2] = {{0,1},{0,2},{3,2}};
        r3 = mc_solve(w, 4, e, 3);  /* expect 13 */
    }

    /*
     * Pack:
     *   n_tests  = 3
     *   metric_a = r1 - r2 - 10 + 2 = 14 - 0 - 10 + 2 = 6
     *   metric_b = r3 - 8 = 13 - 8 = 5
     *   Bytes: 3, 6, 5 — distinct and non-zero.
     *   Wait: 3 and 5 are distinct. 6 != 3, 6 != 5. OK.
     */
    uint32_t ma = (uint32_t)(r1 - r2 - 10 + 2) & 0xFF;
    uint32_t mb = (uint32_t)(r3 - 8) & 0xFF;
    return (3u << 16) | (ma << 8) | mb;
}

void _start(void) {
    g_result = run_mc_tests();
    while (1) {}
}
