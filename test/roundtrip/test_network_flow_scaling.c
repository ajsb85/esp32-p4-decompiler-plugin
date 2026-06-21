/*
 * test_network_flow_scaling.c
 * Capacity-scaling max-flow (Gabow's algorithm variant).
 * Algorithm: runs BFS/DFS augmentation only along edges whose residual
 *   capacity is >= the current scale delta.  Delta starts at the
 *   highest power of 2 <= max_capacity and is halved each phase until
 *   delta == 0.  Within each phase augmenting paths are found by DFS.
 *   This gives O(E^2 log U) overall where U is max capacity.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── graph ─────────────────────────────────────────────────────────── */

#define NFS_V   8
#define NFS_E   64    /* edge-list capacity (half-edges)  */

static int nfs_to  [NFS_E];
static int nfs_cap [NFS_E];
static int nfs_nxt [NFS_E];
static int nfs_head[NFS_V];
static int nfs_iter[NFS_V];   /* current-arc pointer            */
static int nfs_enum;

static void nfs_init(void) {
    for (int i = 0; i < NFS_V; i++) nfs_head[i] = -1;
    nfs_enum = 0;
}

static void nfs_add_edge(int u, int v, int cap) {
    nfs_to[nfs_enum]  = v; nfs_cap[nfs_enum]  = cap;
    nfs_nxt[nfs_enum] = nfs_head[u]; nfs_head[u] = nfs_enum++;

    nfs_to[nfs_enum]  = u; nfs_cap[nfs_enum]  = 0;   /* reverse */
    nfs_nxt[nfs_enum] = nfs_head[v]; nfs_head[v] = nfs_enum++;
}

/* ── DFS augmentation with delta threshold ─────────────────────────── */

#define NFS_INF 0x7fffffff

static int nfs_visited[NFS_V];
static int nfs_dfs(int v, int t, int pushed, int delta) {
    if (v == t) return pushed;
    nfs_visited[v] = 1;
    for (; nfs_iter[v] != -1; nfs_iter[v] = nfs_nxt[nfs_iter[v]]) {
        int e = nfs_iter[v];
        int u = nfs_to[e];
        if (nfs_visited[u] || nfs_cap[e] < delta) continue;
        int d = nfs_dfs(u, t, pushed < nfs_cap[e] ? pushed : nfs_cap[e], delta);
        if (d > 0) {
            nfs_cap[e]     -= d;
            nfs_cap[e ^ 1] += d;
            return d;
        }
    }
    return 0;
}

static int nfs_max_flow(int s, int t, int max_cap) {
    int flow = 0;
    /* find highest power of 2 <= max_cap */
    int delta = 1;
    while (delta <= max_cap) delta <<= 1;
    delta >>= 1;

    while (delta >= 1) {
        while (1) {
            for (int i = 0; i < NFS_V; i++) {
                nfs_iter[i]    = nfs_head[i];
                nfs_visited[i] = 0;
            }
            int f = nfs_dfs(s, t, NFS_INF, delta);
            if (f == 0) break;
            flow += f;
        }
        delta >>= 1;
    }
    return flow;
}

/* ── tests ─────────────────────────────────────────────────────────── */
static uint32_t run_nfs_tests(void) {
    /*
     * Test 1: classic 4-node network
     *   S=0, T=3
     *   0->1 cap 10, 0->2 cap 10, 1->3 cap 10, 2->3 cap 10, 1->2 cap 1
     *   Max flow = 20
     */
    nfs_init();
    nfs_add_edge(0, 1, 10);
    nfs_add_edge(0, 2, 10);
    nfs_add_edge(1, 3, 10);
    nfs_add_edge(2, 3, 10);
    nfs_add_edge(1, 2, 1);
    int f1 = nfs_max_flow(0, 3, 10);   /* expect 20 */

    /*
     * Test 2: bottleneck network
     *   S=0, T=3
     *   0->1 cap 5, 1->2 cap 3, 2->3 cap 7
     *   Max flow = 3 (bottleneck at 1->2)
     */
    nfs_init();
    nfs_add_edge(0, 1, 5);
    nfs_add_edge(1, 2, 3);
    nfs_add_edge(2, 3, 7);
    int f2 = nfs_max_flow(0, 3, 7);    /* expect 3 */

    /*
     * Test 3: parallel paths
     *   S=0, T=4: 0->1 cap 4, 0->2 cap 4, 1->4 cap 4, 2->4 cap 4,
     *             0->3 cap 8, 3->4 cap 8
     *   Max flow = 16
     */
    nfs_init();
    nfs_add_edge(0, 1, 4);
    nfs_add_edge(0, 2, 4);
    nfs_add_edge(1, 4, 4);
    nfs_add_edge(2, 4, 4);
    nfs_add_edge(0, 3, 8);
    nfs_add_edge(3, 4, 8);
    int f3 = nfs_max_flow(0, 4, 8);    /* expect 16 */

    /*
     * Pack: n_tests=3, metric_a=f1/4=5, metric_b=f3/8=2
     * (3<<16)|(5<<8)|2 = 0x030502 — all non-zero distinct ✓
     */
    (void)f2;
    return (3u << 16) | ((uint32_t)(f1 / 4) << 8) | (uint32_t)(f3 / 8);
}

void _start(void) {
    g_result = run_nfs_tests();
    while (1) {}
}
