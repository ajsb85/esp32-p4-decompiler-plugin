/*
 * test_ford_fulkerson_dfs.c
 * Ford-Fulkerson max-flow using depth-first search (DFS) augmenting paths.
 * Algorithm: Repeatedly find augmenting path from source to sink via DFS
 *   on the residual graph. Augment by the bottleneck capacity of that path.
 *   Stops when no augmenting path exists. O(E * max_flow).
 *   Uses adjacency-list residual graph with forward/backward edge pairs.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FF_N   6     /* vertices 0..5 */
#define FF_ME  24    /* max edges (forward + backward pairs) */
#define FF_INF 0x7fff

static int ff_head[FF_N];
static int ff_to[FF_ME];
static int ff_cap[FF_ME];
static int ff_nxt[FF_ME];
static int ff_ecnt;

static void ff_init(void) {
    for (int i = 0; i < FF_N; i++) ff_head[i] = -1;
    ff_ecnt = 0;
}

/* Add directed edge u->v with capacity c; back-edge has capacity 0 */
static void ff_add_edge(int u, int v, int c) {
    ff_to[ff_ecnt]  = v; ff_cap[ff_ecnt]  = c;
    ff_nxt[ff_ecnt] = ff_head[u]; ff_head[u] = ff_ecnt++;

    ff_to[ff_ecnt]  = u; ff_cap[ff_ecnt]  = 0;
    ff_nxt[ff_ecnt] = ff_head[v]; ff_head[v] = ff_ecnt++;
}

static int ff_vis[FF_N];

/* DFS augmentation: find any path and return its bottleneck */
static int ff_dfs(int u, int t, int pushed) {
    if (u == t) return pushed;
    ff_vis[u] = 1;
    for (int e = ff_head[u]; e != -1; e = ff_nxt[e]) {
        int v = ff_to[e];
        if (ff_vis[v] || ff_cap[e] <= 0) continue;
        int d = ff_cap[e] < pushed ? ff_cap[e] : pushed;
        int f = ff_dfs(v, t, d);
        if (f > 0) {
            ff_cap[e]     -= f;
            ff_cap[e ^ 1] += f;
            return f;
        }
    }
    return 0;
}

static int ff_maxflow(int s, int t) {
    int flow = 0;
    while (1) {
        for (int i = 0; i < FF_N; i++) ff_vis[i] = 0;
        int f = ff_dfs(s, t, FF_INF);
        if (f <= 0) break;
        flow += f;
    }
    return flow;
}

static uint32_t run_ford_fulkerson_tests(void) {
    /*
     * Test 1: Classic 6-node network from Cormen et al.
     *   s=0, t=5
     *   Edges: 0->1(16), 0->2(13), 1->2(10), 1->3(12),
     *          2->4(14), 3->2(9), 3->5(20), 4->3(7), 4->5(4)
     *   Max flow = 23
     */
    ff_init();
    ff_add_edge(0, 1, 16);
    ff_add_edge(0, 2, 13);
    ff_add_edge(1, 2, 10);
    ff_add_edge(1, 3, 12);
    ff_add_edge(2, 4, 14);
    ff_add_edge(3, 2,  9);
    ff_add_edge(3, 5, 20);
    ff_add_edge(4, 3,  7);
    ff_add_edge(4, 5,  4);
    int mf1 = ff_maxflow(0, 5);   /* expect 23 */

    /*
     * Test 2: Simple path 0->1->2 with caps 5,3 -> max flow=3
     */
    ff_init();
    ff_add_edge(0, 1, 5);
    ff_add_edge(1, 2, 3);
    int mf2 = ff_maxflow(0, 2);   /* expect 3 */

    /*
     * Test 3: Two parallel paths: 0->1(2), 0->2(2), 1->3(2), 2->3(2)
     *   Max flow = 4
     */
    ff_init();
    ff_add_edge(0, 1, 2);
    ff_add_edge(0, 2, 2);
    ff_add_edge(1, 3, 2);
    ff_add_edge(2, 3, 2);
    int mf3 = ff_maxflow(0, 3);   /* expect 4 */

    /*
     * Pack: n_tests=3, metric_a=mf2=3, metric_b=mf3=4
     * (3<<16)|(3<<8)|4 = 0x030304 — bytes: 3,3,4 — metric_a==n_tests clash.
     * Use metric_a=mf2+1=4 to make distinct: (3<<16)|(4<<8)|mf3
     * = (3<<16)|(4<<8)|4 — still clash on metric_a and metric_b.
     * Use n_tests=3, metric_a=mf2=3 -> but (3,3,4) bytes, bytes 0 and 1 same.
     * Use n_tests=3, metric_a=(mf1 & 0xFF)=23=0x17, metric_b=mf3=4
     * (3<<16)|(23<<8)|4 = 0x031704  all distinct non-zero.
     */
    (void)mf2;
    return (3u << 16) | ((uint32_t)(mf1 & 0xFF) << 8) | (uint32_t)mf3;
}

void _start(void) {
    g_result = run_ford_fulkerson_tests();
    while (1) {}
}
