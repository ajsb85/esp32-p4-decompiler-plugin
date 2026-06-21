/*
 * test_euler_path_hierholzer.c
 * Eulerian path / circuit using Hierholzer's algorithm.
 * Algorithm: iterative stack-based Hierholzer that finds an Eulerian
 *   circuit in an undirected multigraph.  At each step the current
 *   vertex is pushed; when no unused edge remains the vertex is appended
 *   to the path in reverse.  The algorithm counts how many edges are
 *   traversed (= E) and the length of the resulting path (= E+1 for a
 *   circuit, same start==end vertex).
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── graph representation ─────────────────────────────────────────── */

#define EPH_V    6      /* vertices 0..5          */
#define EPH_E   14      /* directed half-edges     */

/* adjacency list stored as a flat edge array with next[] links        */
static int eph_to  [EPH_E * 2];   /* destination of each half-edge     */
static int eph_used[EPH_E * 2];   /* 1 if traversed                    */
static int eph_next[EPH_E * 2];   /* next edge in adj-list             */
static int eph_head[EPH_V];       /* head of adj-list for each vertex  */
static int eph_cur [EPH_V];       /* current edge pointer (Hierholzer) */
static int eph_enum;              /* total half-edges added             */

static void eph_init(void) {
    for (int i = 0; i < EPH_V; i++) eph_head[i] = -1;
    eph_enum = 0;
}

static void eph_add_edge(int u, int v) {
    /* add both directed halves */
    eph_to[eph_enum]   = v; eph_used[eph_enum] = 0;
    eph_next[eph_enum] = eph_head[u]; eph_head[u] = eph_enum++;

    eph_to[eph_enum]   = u; eph_used[eph_enum] = 0;
    eph_next[eph_enum] = eph_head[v]; eph_head[v] = eph_enum++;
}

/* ── Hierholzer (iterative) ───────────────────────────────────────── */

#define EPH_STACK 64
static int eph_stk[EPH_STACK];
static int eph_stk_top;
static int eph_path[EPH_STACK];
static int eph_path_len;

static int eph_hierholzer(int start) {
    for (int i = 0; i < EPH_V; i++) eph_cur[i] = eph_head[i];

    eph_stk_top  = 0;
    eph_path_len = 0;
    eph_stk[eph_stk_top++] = start;

    while (eph_stk_top > 0) {
        int v = eph_stk[eph_stk_top - 1];
        int found = 0;
        while (eph_cur[v] != -1) {
            int e = eph_cur[v];
            eph_cur[v] = eph_next[e];
            if (eph_used[e]) continue;
            eph_used[e] = 1;
            /* mark reverse edge used too (e^1 is the paired half) */
            eph_used[e ^ 1] = 1;
            eph_stk[eph_stk_top++] = eph_to[e];
            found = 1;
            break;
        }
        if (!found) {
            eph_path[eph_path_len++] = eph_stk[--eph_stk_top];
        }
    }
    return eph_path_len;   /* path length = E+1 for a circuit */
}

/* ── check all edges used ─────────────────────────────────────────── */
static int eph_all_used(void) {
    for (int i = 0; i < eph_enum; i++)
        if (!eph_used[i]) return 0;
    return 1;
}

/* ── tests ────────────────────────────────────────────────────────── */
static uint32_t run_eph_tests(void) {
    /*
     * Test 1: K4 (complete graph on 4 vertices).
     * 6 undirected edges, every vertex has degree 3 — wait, deg 3 is odd,
     * no Eulerian circuit. Use K4 minus one edge: vertices 0-3,
     * edges: 0-1, 0-2, 1-2, 1-3, 2-3 → each vertex degree:
     *   0→2, 1→3-nope. Try a different graph.
     *
     * Build a graph where all vertices have even degree:
     * vertices 0-3, edges: 0-1, 1-2, 2-3, 3-0, 0-2, 1-3
     * degrees: 0→3? no. 0: edges to 1,3,2 → degree 3. Not even.
     *
     * Use a simple triangle + repeated edge:
     * 0-1, 1-2, 2-0, 0-1 (multigraph)
     * degrees: 0→3? no.
     *
     * Safe choice: two triangles sharing vertex 0.
     * 0-1,1-2,2-0 and 0-3,3-4,4-0
     * degrees: 0→4(even), 1→2, 2→2, 3→2, 4→2. All even!
     * E = 6 edges, path length = 7.
     */
    eph_init();
    eph_add_edge(0, 1); eph_add_edge(1, 2); eph_add_edge(2, 0);
    eph_add_edge(0, 3); eph_add_edge(3, 4); eph_add_edge(4, 0);
    int plen1 = eph_hierholzer(0);
    int ok1   = eph_all_used() ? 1 : 0;

    /*
     * Test 2: single cycle 0-1-2-3-4-5-0
     * degrees all 2, E=6, path length=7
     */
    eph_init();
    eph_add_edge(0, 1); eph_add_edge(1, 2); eph_add_edge(2, 3);
    eph_add_edge(3, 4); eph_add_edge(4, 5); eph_add_edge(5, 0);
    int plen2 = eph_hierholzer(0);
    int ok2   = eph_all_used() ? 1 : 0;

    /*
     * Pack: n_tests=2, metric_a=plen1=7, metric_b=(ok1+ok2)*3=6
     * (2<<16)|(7<<8)|6 = 0x020706  all non-zero and distinct
     */
    (void)plen2; (void)ok2;
    return (2u << 16) | ((uint32_t)plen1 << 8) | (uint32_t)((ok1 + ok2) * 3u);
}

void _start(void) {
    g_result = run_eph_tests();
    while (1) {}
}
