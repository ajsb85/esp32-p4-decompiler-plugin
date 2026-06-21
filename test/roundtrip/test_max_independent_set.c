/*
 * test_max_independent_set.c
 * Maximum Independent Set (MIS) via bitmask branch-and-bound.
 * Algorithm: For small graphs (N <= 20), use bitmask DP / exhaustive search
 *   with pruning.  An independent set is a subset S of vertices such that no
 *   two vertices in S are adjacent.  MIS = maximum cardinality such subset.
 *   The bitmask approach encodes adjacency as uint32 bitmasks (adj[v]).
 *   Branch-and-bound: pick the vertex u in the remaining candidate set with
 *   maximum degree within the candidates (Bron-Kerbosch style), either
 *   include or exclude it, prune when current + |candidates| <= best.
 *   Time: O*(2^N) worst case but fast in practice via pruning.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MIS_N  16   /* max vertices */

static uint32_t mis_adj[MIS_N];  /* adjacency bitmask per vertex */
static int      mis_nv;
static int      mis_best;

static void mis_reset(int nv) {
    mis_nv   = nv;
    mis_best = 0;
    for (int i = 0; i < nv; i++) mis_adj[i] = 0u;
}

static void mis_add_edge(int u, int v) {
    mis_adj[u] |= (1u << v);
    mis_adj[v] |= (1u << u);
}

/* Popcount of a uint32 */
static int mis_popcount(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    x = (x + (x >> 4)) & 0x0f0f0f0fu;
    return (int)((x * 0x01010101u) >> 24);
}

/* Branch-and-bound MIS search.
 *   candidates = bitmask of vertices still available
 *   cur_size   = size of current partial independent set
 */
static void mis_search(uint32_t candidates, int cur_size) {
    if (candidates == 0u) {
        if (cur_size > mis_best) mis_best = cur_size;
        return;
    }
    /* Pruning: even if we take all candidates we can't beat best */
    if (cur_size + mis_popcount(candidates) <= mis_best) return;

    /* Pick the vertex in candidates with the highest degree within candidates */
    int best_v = -1, best_deg = -1;
    for (int v = 0; v < mis_nv; v++) {
        if (!(candidates & (1u << v))) continue;
        int deg = mis_popcount(mis_adj[v] & candidates);
        if (deg > best_deg) { best_deg = deg; best_v = v; }
    }

    uint32_t mask_v = 1u << best_v;

    /* Branch 1: include best_v — remove best_v and its neighbors */
    uint32_t new_cand = candidates & ~mask_v & ~mis_adj[best_v];
    mis_search(new_cand, cur_size + 1);

    /* Branch 2: exclude best_v */
    mis_search(candidates & ~mask_v, cur_size);
}

static int mis_solve(void) {
    mis_best = 0;
    uint32_t all = (mis_nv < 32) ? ((1u << mis_nv) - 1u) : 0xFFFFFFFFu;
    mis_search(all, 0);
    return mis_best;
}

static uint32_t run_mis_tests(void) {
    /*
     * Test 1: Cycle C6 (6 vertices)
     * Edges: 0-1, 1-2, 2-3, 3-4, 4-5, 5-0
     * MIS = {0,2,4} or {1,3,5} -> size 3
     */
    mis_reset(6);
    mis_add_edge(0,1); mis_add_edge(1,2); mis_add_edge(2,3);
    mis_add_edge(3,4); mis_add_edge(4,5); mis_add_edge(5,0);
    int r1 = mis_solve();  /* expect 3 */

    /*
     * Test 2: Complete bipartite K_{2,3} (5 vertices: 0,1 on left; 2,3,4 on right)
     * MIS = right side {2,3,4} -> size 3
     */
    mis_reset(5);
    for (int u = 0; u <= 1; u++)
        for (int v = 2; v <= 4; v++)
            mis_add_edge(u, v);
    int r2 = mis_solve();  /* expect 3 */

    /*
     * Test 3: Petersen graph (10 vertices, 15 edges)
     * Outer 5-cycle: 0-1-2-3-4-0
     * Inner pentagram: 5-7-9-6-8-5
     * Spokes: 0-5, 1-6, 2-7, 3-8, 4-9
     * MIS = 4
     */
    mis_reset(10);
    /* outer cycle */
    mis_add_edge(0,1); mis_add_edge(1,2); mis_add_edge(2,3);
    mis_add_edge(3,4); mis_add_edge(4,0);
    /* inner pentagram */
    mis_add_edge(5,7); mis_add_edge(7,9); mis_add_edge(9,6);
    mis_add_edge(6,8); mis_add_edge(8,5);
    /* spokes */
    mis_add_edge(0,5); mis_add_edge(1,6); mis_add_edge(2,7);
    mis_add_edge(3,8); mis_add_edge(4,9);
    int r3 = mis_solve();  /* expect 4 */

    /*
     * Pack: n_tests=3, metric_a = r1+r2 = 3+3 = 6 (but 3+3=6 ok)
     *       metric_b = r3 = 4
     * (3<<16)|(6<<8)|4 = 0x030604 all distinct non-zero. Good.
     */
    return (3u << 16) | (((uint32_t)(r1 + r2) & 0xFF) << 8) | ((uint32_t)r3 & 0xFF);
}

void _start(void) {
    g_result = run_mis_tests();
    while (1) {}
}
