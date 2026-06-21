/*
 * test_min_vertex_cover.c
 * Minimum vertex cover in a bipartite graph via König's theorem.
 * Algorithm: König's theorem states that in a bipartite graph the
 *   minimum vertex cover equals the maximum matching.
 *   Steps: (1) find max matching using augmenting-path BFS (Hopcroft-
 *   Karp lite / standard augmenting path), (2) find minimum vertex
 *   cover using the König construction: alternating-path reachability
 *   from unmatched left vertices, then take (L not reachable) ∪
 *   (R reachable).
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── bipartite graph ──────────────────────────────────────────────── */

#define MVC_L   6    /* left vertices  0..L-1       */
#define MVC_R   6    /* right vertices 0..R-1       */
#define MVC_ADJ 36   /* adjacency storage            */

static int mvc_adj [MVC_L][MVC_R];   /* adj[u][v] = 1 if edge u-v    */
static int mvc_ml  [MVC_L];          /* matching: left->right (-1=free)*/
static int mvc_mr  [MVC_R];          /* matching: right->left (-1=free)*/

static void mvc_init(void) {
    for (int u = 0; u < MVC_L; u++) {
        mvc_ml[u] = -1;
        for (int v = 0; v < MVC_R; v++) mvc_adj[u][v] = 0;
    }
    for (int v = 0; v < MVC_R; v++) mvc_mr[v] = -1;
}

static void mvc_add_edge(int u, int v) {
    mvc_adj[u][v] = 1;
}

/* augmenting path DFS from left vertex u */
static int mvc_visited[MVC_R];
static int mvc_dfs(int u) {
    for (int v = 0; v < MVC_R; v++) {
        if (!mvc_adj[u][v] || mvc_visited[v]) continue;
        mvc_visited[v] = 1;
        if (mvc_mr[v] == -1 || mvc_dfs(mvc_mr[v])) {
            mvc_ml[u] = v;
            mvc_mr[v] = u;
            return 1;
        }
    }
    return 0;
}

static int mvc_max_matching(void) {
    int match = 0;
    for (int u = 0; u < MVC_L; u++) {
        for (int v = 0; v < MVC_R; v++) mvc_visited[v] = 0;
        if (mvc_dfs(u)) match++;
    }
    return match;
}

/* König construction: find min vertex cover size */
static int mvc_reach_l[MVC_L];
static int mvc_reach_r[MVC_R];

static int mvc_vertex_cover(void) {
    int matching = mvc_max_matching();

    /* BFS/DFS from unmatched left vertices via alternating paths */
    /* init reachability */
    for (int i = 0; i < MVC_L; i++) mvc_reach_l[i] = 0;
    for (int i = 0; i < MVC_R; i++) mvc_reach_r[i] = 0;

    /* iterative alternating-path DFS using a small queue */
    static int ql[MVC_L], qr[MVC_R];
    int ql_h = 0, ql_t = 0, qr_h = 0, qr_t = 0;

    /* seed: unmatched left vertices */
    for (int u = 0; u < MVC_L; u++) {
        if (mvc_ml[u] == -1) {
            mvc_reach_l[u] = 1;
            ql[ql_t++] = u;
        }
    }

    while (ql_h < ql_t || qr_h < qr_t) {
        while (ql_h < ql_t) {
            int u = ql[ql_h++];
            /* follow unmatched edges to right */
            for (int v = 0; v < MVC_R; v++) {
                if (mvc_adj[u][v] && !mvc_reach_r[v] && mvc_ml[u] != v) {
                    mvc_reach_r[v] = 1;
                    qr[qr_t++] = v;
                }
            }
        }
        while (qr_h < qr_t) {
            int v = qr[qr_h++];
            /* follow matched edge to left */
            int u = mvc_mr[v];
            if (u != -1 && !mvc_reach_l[u]) {
                mvc_reach_l[u] = 1;
                ql[ql_t++] = u;
            }
        }
    }

    /* König: cover = (L not reachable) ∪ (R reachable) */
    int cover = 0;
    for (int u = 0; u < MVC_L; u++) if (!mvc_reach_l[u] && mvc_ml[u] != -1) cover++;
    for (int v = 0; v < MVC_R; v++) if (mvc_reach_r[v]) cover++;

    (void)matching;
    return cover;
}

/* ── tests ─────────────────────────────────────────────────────────── */
static uint32_t run_mvc_tests(void) {
    /*
     * Test 1: K_{3,3} complete bipartite graph.
     * Max matching = 3, min vertex cover = 3.
     */
    mvc_init();
    for (int u = 0; u < 3; u++)
        for (int v = 0; v < 3; v++)
            mvc_add_edge(u, v);
    int c1 = mvc_vertex_cover();   /* expect 3 */

    /*
     * Test 2: path graph matching L={0,1,2} R={0,1,2}
     * edges: 0-0, 1-1, 2-2 (perfect matching 1-1-1 matching)
     * Min vertex cover = 3 (must cover all 3 edges, no shared vertex).
     * Actually min vertex cover of a perfect matching = n (one per edge).
     * Use a richer graph: 0-0,0-1,1-1,2-2
     * Matching: 0->1,1->1? no conflict. match={0->0,1->1,2->2}=3
     * Cover: 3 via König.
     */
    mvc_init();
    mvc_add_edge(0, 0); mvc_add_edge(0, 1);
    mvc_add_edge(1, 1); mvc_add_edge(1, 2);
    mvc_add_edge(2, 2); mvc_add_edge(2, 0);
    int c2 = mvc_vertex_cover();   /* expect 3 */

    /*
     * Test 3: star graph: left vertex 0 connects to all 4 right vertices.
     * Max matching = 1, min cover = 1 (just left vertex 0).
     */
    mvc_init();
    for (int v = 0; v < 4; v++) mvc_add_edge(0, v);
    int c3 = mvc_vertex_cover();   /* expect 1 */

    /*
     * Pack: n_tests=3, metric_a=c1*2=6, metric_b=c3+4=5
     * (3<<16)|(6<<8)|5 = 0x030605 — 3,6,5 all distinct non-zero ✓
     */
    (void)c2;
    return (3u << 16) | ((uint32_t)(c1 * 2u) << 8) | (uint32_t)(c3 + 4u);
}

void _start(void) {
    g_result = run_mvc_tests();
    while (1) {}
}
