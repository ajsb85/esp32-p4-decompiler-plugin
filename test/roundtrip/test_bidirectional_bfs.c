/*
 * test_bidirectional_bfs.c
 * Bidirectional BFS (meet-in-the-middle BFS) for shortest path on an
 * unweighted undirected graph.
 * Algorithm: expand BFS frontiers alternately from source and target.
 *   When a node from one frontier is found in the other's visited set,
 *   the path length is dist_fwd[node] + dist_bwd[node].
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BB_N    8      /* vertices 0..7 */
#define BB_INF  255

/* Adjacency list via flat CSR-style arrays */
static const int bb_edges[][2] = {
    {0,1},{0,2},{1,3},{2,3},{3,4},{4,5},{5,6},{6,7},{4,7}
};
#define BB_NE  9

static uint8_t bb_adj[BB_N][BB_N];

static void bb_build(void) {
    for (int i = 0; i < BB_NE; i++) {
        int u = bb_edges[i][0], v = bb_edges[i][1];
        bb_adj[u][v] = 1; bb_adj[v][u] = 1;
    }
}

/* Bidirectional BFS: returns shortest path length from src to dst, or BB_INF */
static uint8_t bb_dist_fwd[BB_N];
static uint8_t bb_dist_bwd[BB_N];
static int     bb_queue[BB_N * 2];

static int bb_bfs(int src, int dst) {
    if (src == dst) return 0;

    for (int i = 0; i < BB_N; i++) {
        bb_dist_fwd[i] = BB_INF;
        bb_dist_bwd[i] = BB_INF;
    }

    int fq_head = 0, fq_tail = 0;
    int bq_head = BB_N, bq_tail = BB_N;

    bb_dist_fwd[src] = 0; bb_queue[fq_tail++] = src;
    bb_dist_bwd[dst] = 0; bb_queue[bq_tail++] = dst;

    int best = BB_INF;

    while (fq_head < fq_tail || bq_head < bq_tail) {
        /* Expand forward frontier */
        if (fq_head < fq_tail) {
            int u = bb_queue[fq_head++];
            for (int v = 0; v < BB_N; v++) {
                if (!bb_adj[u][v]) continue;
                if (bb_dist_fwd[v] == BB_INF) {
                    bb_dist_fwd[v] = bb_dist_fwd[u] + 1;
                    bb_queue[fq_tail++] = v;
                }
                /* Check meet */
                if (bb_dist_bwd[v] != BB_INF) {
                    int d = (int)bb_dist_fwd[v] + (int)bb_dist_bwd[v];
                    if (d < best) best = d;
                }
            }
        }
        /* Expand backward frontier */
        if (bq_head < bq_tail) {
            int u = bb_queue[bq_head++];
            for (int v = 0; v < BB_N; v++) {
                if (!bb_adj[u][v]) continue;
                if (bb_dist_bwd[v] == BB_INF) {
                    bb_dist_bwd[v] = bb_dist_bwd[u] + 1;
                    bb_queue[bq_tail++] = v;
                }
                /* Check meet */
                if (bb_dist_fwd[v] != BB_INF) {
                    int d = (int)bb_dist_fwd[v] + (int)bb_dist_bwd[v];
                    if (d < best) best = d;
                }
            }
        }
        if (best != BB_INF) break;
    }
    return (uint8_t)best;
}

static uint32_t run_bidirectional_bfs_tests(void) {
    bb_build();

    /* Test 1: 0 -> 7.  Graph: 0-1-3-4-7 = length 4, or 0-2-3-4-7 = 4 */
    int d1 = bb_bfs(0, 7);  /* expect 4 */

    /* Test 2: 0 -> 5.  0-1-3-4-5 = length 4 */
    int d2 = bb_bfs(0, 5);  /* expect 4 */

    /* Test 3: 5 -> 6.  5-6 = length 1 */
    int d3 = bb_bfs(5, 6);  /* expect 1 */

    /*
     * Pack: n_tests=3, metric_a=d1=4, metric_b=d2+d3=5
     * (3<<16)|(4<<8)|5 = 0x030405  all non-zero distinct
     */
    uint32_t metric_b = (uint32_t)(d2 + d3);
    return (3u << 16) | ((uint32_t)d1 << 8) | metric_b;
}

void _start(void) {
    g_result = run_bidirectional_bfs_tests();
    while (1) {}
}
