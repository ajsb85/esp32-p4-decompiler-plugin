/*
 * test_articulation_points_bridges.c
 * Articulation Points and Bridges detection via iterative DFS (Tarjan).
 * Algorithm: In an undirected graph, an articulation point (cut vertex) is a
 *   vertex whose removal disconnects the graph.  A bridge is an edge whose
 *   removal disconnects the graph.  Both can be found in O(V+E) using a
 *   single DFS tracking disc[] (discovery time) and low[] (lowest discovery
 *   time reachable via back edges in the DFS subtree).
 *   A vertex u is an articulation point if:
 *     (a) it is the DFS root with 2+ children, OR
 *     (b) it has a child v with low[v] >= disc[u].
 *   An edge (u,v) is a bridge if low[v] > disc[u].
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define APB_MAXV  32
#define APB_MAXE  128

static int apb_nv;
static int apb_head[APB_MAXV];
static int apb_to[APB_MAXE * 2];
static int apb_nxt[APB_MAXE * 2];
static int apb_eid[APB_MAXE * 2];  /* original edge id for bridge check */
static int apb_ecnt;

static int apb_disc[APB_MAXV];
static int apb_low[APB_MAXV];
static int apb_parent[APB_MAXV];
static int apb_is_ap[APB_MAXV];   /* articulation point flag */
static int apb_is_bridge[APB_MAXE]; /* bridge flag per original edge */
static int apb_timer;

static void apb_reset(int nv) {
    apb_nv   = nv;
    apb_ecnt = 0;
    for (int i = 0; i < nv; i++) {
        apb_head[i]   = -1;
        apb_disc[i]   = -1;
        apb_low[i]    = 0;
        apb_parent[i] = -1;
        apb_is_ap[i]  = 0;
    }
    for (int i = 0; i < APB_MAXE; i++) apb_is_bridge[i] = 0;
    apb_timer = 0;
}

static void apb_add_edge(int u, int v) {
    int eid = apb_ecnt / 2;
    apb_to[apb_ecnt]  = v;
    apb_nxt[apb_ecnt] = apb_head[u];
    apb_eid[apb_ecnt] = eid;
    apb_head[u]       = apb_ecnt++;
    apb_to[apb_ecnt]  = u;
    apb_nxt[apb_ecnt] = apb_head[v];
    apb_eid[apb_ecnt] = eid;
    apb_head[v]       = apb_ecnt++;
}

/* Iterative Tarjan DFS using explicit stack */
static int  apb_stk[APB_MAXV];
static int  apb_stk_e[APB_MAXV];   /* current edge pointer */
static int  apb_stk_child[APB_MAXV]; /* DFS child count (for root check) */

static void apb_dfs(int root) {
    int top = 0;
    apb_stk[0]       = root;
    apb_stk_e[0]     = apb_head[root];
    apb_stk_child[0] = 0;
    apb_disc[root]   = apb_low[root] = apb_timer++;

    while (top >= 0) {
        int u = apb_stk[top];
        int e = apb_stk_e[top];
        if (e == -1) {
            /* Done with u: propagate low[] to parent */
            if (top > 0) {
                int par = apb_stk[top - 1];
                if (apb_low[u] < apb_low[par]) apb_low[par] = apb_low[u];
                /* Articulation point check (non-root) */
                if (apb_low[u] >= apb_disc[par]) {
                    apb_is_ap[par] = 1;
                }
                /* Bridge check */
                if (apb_low[u] > apb_disc[par]) {
                    /* find edge id between par and u */
                    for (int ex = apb_head[par]; ex != -1; ex = apb_nxt[ex]) {
                        if (apb_to[ex] == u) {
                            apb_is_bridge[apb_eid[ex]] = 1;
                            break;
                        }
                    }
                }
            }
            top--;
        } else {
            int v  = apb_to[e];
            int eid = apb_eid[e];
            apb_stk_e[top] = apb_nxt[e];
            (void)eid;
            if (apb_disc[v] == -1) {
                /* Tree edge */
                apb_parent[v]   = u;
                apb_disc[v]     = apb_low[v] = apb_timer++;
                apb_stk_child[top]++;
                top++;
                apb_stk[top]       = v;
                apb_stk_e[top]     = apb_head[v];
                apb_stk_child[top] = 0;
            } else if (v != apb_parent[u]) {
                /* Back edge: update low */
                if (apb_disc[v] < apb_low[u]) apb_low[u] = apb_disc[v];
            }
        }
    }
    /* Root is AP only if it has 2+ DFS children */
    if (apb_stk_child[0] < 2) apb_is_ap[root] = 0;
}

static void apb_find_all(void) {
    for (int i = 0; i < apb_nv; i++) {
        if (apb_disc[i] == -1) apb_dfs(i);
    }
}

static int apb_count_ap(void) {
    int c = 0;
    for (int i = 0; i < apb_nv; i++) c += apb_is_ap[i];
    return c;
}

static int apb_count_bridges(void) {
    int c = 0, edges = apb_ecnt / 2;
    for (int i = 0; i < edges; i++) c += apb_is_bridge[i];
    return c;
}

static uint32_t run_apb_tests(void) {
    int ap1, br1, ap2, br2, ap3, br3;

    /*
     * Test 1: Simple path 0-1-2-3
     * All intermediate vertices (1,2) are APs, all 3 edges are bridges.
     */
    apb_reset(4);
    apb_add_edge(0, 1);
    apb_add_edge(1, 2);
    apb_add_edge(2, 3);
    apb_find_all();
    ap1 = apb_count_ap();    /* expect 2 */
    br1 = apb_count_bridges(); /* expect 3 */

    /*
     * Test 2: Triangle + pendant: 0-1-2-0, then 2-3
     * Vertex 2 is an AP (connecting triangle to pendant).
     * Edge 2-3 is a bridge.
     */
    apb_reset(4);
    apb_add_edge(0, 1);
    apb_add_edge(1, 2);
    apb_add_edge(2, 0);
    apb_add_edge(2, 3);
    apb_find_all();
    ap2 = apb_count_ap();    /* expect 1 */
    br2 = apb_count_bridges(); /* expect 1 */

    /*
     * Test 3: Two triangles sharing a single vertex (bowtie): 0-1-2-0 and 2-3-4-2
     * Vertex 2 is the only AP. No bridges (both triangles are 2-edge-connected).
     */
    apb_reset(5);
    apb_add_edge(0, 1);
    apb_add_edge(1, 2);
    apb_add_edge(2, 0);
    apb_add_edge(2, 3);
    apb_add_edge(3, 4);
    apb_add_edge(4, 2);
    apb_find_all();
    ap3 = apb_count_ap();    /* expect 1 */
    br3 = apb_count_bridges(); /* expect 0 */

    /*
     * Pack:
     *   n_tests  = 3
     *   metric_a = ap1 + br1 + ap2 + br2 = 2+3+1+1 = 7
     *   metric_b = ap3*4 + br3*2 + 1 = 4+0+1 = 5
     *   Bytes: 3, 7, 5 — distinct and non-zero.
     */
    uint32_t ma = (uint32_t)(ap1 + br1 + ap2 + br2) & 0xFF;
    uint32_t mb = (uint32_t)(ap3 * 4 + br3 * 2 + 1) & 0xFF;
    return (3u << 16) | (ma << 8) | mb;
}

void _start(void) {
    g_result = run_apb_tests();
    while (1) {}
}
