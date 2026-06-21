/*
 * test_chinese_postman.c
 * Chinese Postman Problem (Route Inspection) on an undirected graph.
 * Finds minimum cost to traverse every edge at least once.
 * Algorithm: find all odd-degree vertices, compute minimum weight perfect
 * matching on them (via bitmask DP for small N), add matched edge weights
 * to total edge weight sum.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CP_MAXN  8
#define CP_INF   0x7fffffff

/* Graph stored as adjacency matrix */
static int32_t cp_dist[CP_MAXN][CP_MAXN];
static int     cp_n;

/* Floyd-Warshall for all-pairs shortest paths */
static int32_t cp_sp[CP_MAXN][CP_MAXN];

static void cp_floyd(void) {
    for (int i = 0; i < cp_n; i++)
        for (int j = 0; j < cp_n; j++)
            cp_sp[i][j] = cp_dist[i][j];
    for (int k = 0; k < cp_n; k++)
        for (int i = 0; i < cp_n; i++)
            for (int j = 0; j < cp_n; j++)
                if (cp_sp[i][k] != CP_INF && cp_sp[k][j] != CP_INF)
                    if (cp_sp[i][k] + cp_sp[k][j] < cp_sp[i][j])
                        cp_sp[i][j] = cp_sp[i][k] + cp_sp[k][j];
}

/* Collect odd-degree vertices */
static int cp_odd[CP_MAXN];
static int cp_odd_n;

static void cp_find_odd(const int *deg) {
    cp_odd_n = 0;
    for (int i = 0; i < cp_n; i++)
        if (deg[i] & 1)
            cp_odd[cp_odd_n++] = i;
}

/* Bitmask DP: minimum weight perfect matching on cp_odd vertices */
static int32_t cp_dp[1 << CP_MAXN];

static int32_t cp_min_matching(void) {
    int m = cp_odd_n;
    int sz = 1 << m;
    for (int mask = 0; mask < sz; mask++) cp_dp[mask] = CP_INF;
    cp_dp[0] = 0;

    for (int mask = 0; mask < sz; mask++) {
        if (cp_dp[mask] == CP_INF) continue;
        /* find lowest unmatched bit */
        int i = -1;
        for (int b = 0; b < m; b++) {
            if (!(mask & (1 << b))) { i = b; break; }
        }
        if (i == -1) continue;
        for (int j = i + 1; j < m; j++) {
            if (mask & (1 << j)) continue;
            int next = mask | (1 << i) | (1 << j);
            int32_t w = cp_sp[cp_odd[i]][cp_odd[j]];
            if (w != CP_INF && cp_dp[mask] + w < cp_dp[next])
                cp_dp[next] = cp_dp[mask] + w;
        }
    }
    return cp_dp[sz - 1];
}

static int32_t cp_solve(const int *deg) {
    /* Total edge weight */
    int32_t total = 0;
    for (int i = 0; i < cp_n; i++)
        for (int j = i + 1; j < cp_n; j++)
            if (cp_dist[i][j] != CP_INF)
                total += cp_dist[i][j];

    cp_floyd();
    cp_find_odd(deg);
    if (cp_odd_n == 0) return total;
    int32_t extra = cp_min_matching();
    return total + extra;
}

static uint32_t run_chinese_postman_tests(void) {
    /*
     * Test 1: Square graph (4 nodes, 4 edges each weight 1)
     * Nodes 0-1-2-3-0, all degrees = 2 (even) => no extra traversal.
     * Total = 4*1 = 4.
     */
    cp_n = 4;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            cp_dist[i][j] = (i == j) ? 0 : CP_INF;
    cp_dist[0][1] = cp_dist[1][0] = 1;
    cp_dist[1][2] = cp_dist[2][1] = 1;
    cp_dist[2][3] = cp_dist[3][2] = 1;
    cp_dist[3][0] = cp_dist[0][3] = 1;
    int deg1[] = {2, 2, 2, 2};
    int32_t r1 = cp_solve(deg1); /* expected 4 */

    /*
     * Test 2: Single edge plus extra — bridge graph
     * 4 nodes: 0-1 (w=3), 1-2 (w=2), 1-3 (w=1)
     * Degrees: 0→1(odd), 1→3(odd), 2→1(odd), 3→1(odd)
     * 4 odd vertices. Match (0,2)=5, (1,3)=1 => sum=6; or (0,3)=4,(1,2)=2 =>6
     * Min matching = min(5+1, 4+2) = 6. Total edges = 3+2+1=6. Answer=12.
     */
    cp_n = 4;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            cp_dist[i][j] = (i == j) ? 0 : CP_INF;
    cp_dist[0][1] = cp_dist[1][0] = 3;
    cp_dist[1][2] = cp_dist[2][1] = 2;
    cp_dist[1][3] = cp_dist[3][1] = 1;
    int deg2[] = {1, 3, 1, 1};
    int32_t r2 = cp_solve(deg2); /* expected 12 */

    /*
     * Test 3: Triangle (3 nodes all odd degree 2... wait degrees are all 2,even)
     * Triangle: all even => answer = total = 1+2+3 = 6
     */
    cp_n = 3;
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            cp_dist[i][j] = (i == j) ? 0 : CP_INF;
    cp_dist[0][1] = cp_dist[1][0] = 1;
    cp_dist[1][2] = cp_dist[2][1] = 2;
    cp_dist[0][2] = cp_dist[2][0] = 3;
    int deg3[] = {2, 2, 2};
    int32_t r3 = cp_solve(deg3); /* expected 6 */

    /*
     * Pack: n_tests=3, metric_a=r2 (12=0x0C), metric_b=r3 (6=0x06)
     * Bytes: 0x03, 0x0C, 0x06 — all non-zero and distinct.
     */
    uint32_t metric_a = (uint32_t)(r2 & 0xFF); /* 12 = 0x0C */
    uint32_t metric_b = (uint32_t)(r3 & 0xFF); /* 6  = 0x06 */
    (void)r1;
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_chinese_postman_tests();
    while (1) {}
}
