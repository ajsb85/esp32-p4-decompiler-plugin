/* test_bitmask_dp_tsp.c
 * Purpose   : Validate bitmask DP for Travelling Salesman Problem (Held-Karp)
 * Algorithm : dp[mask][v] = minimum cost to visit exactly the cities in
 *             `mask`, ending at city v.  Transition: try all unvisited cities.
 *             Final answer: min over all v of dp[(1<<N)-1][v] + dist[v][0].
 * Input     : 4 cities, symmetric distance matrix:
 *               dist[0][1]=10, dist[0][2]=15, dist[0][3]=20
 *               dist[1][2]=35, dist[1][3]=25
 *               dist[2][3]=30  (plus symmetric entries)
 * Expected  : Optimal tour cost = 80  (0→1→3→2→0: 10+25+30+15)
 *             n_cities=4, min_cost_lo=80, start_city=0
 * g_result  = (n_cities << 16) | (min_cost_lo << 8) | start_city
 *           — min_cost_lo = 80 = 0x50, n_cities = 4, start_city = 1
 *             Use start_city=1 (non-zero): tour from city 1
 *             0→1→3→2→0 same cost 80 if we start accounting from 0.
 *             Keep start=0 forbidden (zero byte). Change to n_cities=4,
 *             cost_tens=8 (80/10), start=1: g_result=0x040801
 *             Or: n_cities<<16 | min_cost<<8 | n_cities: 0x045004
 *             But 4 repeated. Use n_cities=4, min_cost=80, n_edges=5:
 *             0x04500x — 0x045005 → bytes 4,80,5 all distinct, non-zero. OK.
 * g_result  = (4 << 16) | (80 << 8) | 5 = 0x045005
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define TSP_N    4
#define TSP_INF  0x7fff

static const int tsp_dist[TSP_N][TSP_N] = {
    {  0, 10, 15, 20 },
    { 10,  0, 35, 25 },
    { 15, 35,  0, 30 },
    { 20, 25, 30,  0 },
};

/* dp[mask][v]: min cost to reach state (mask,v) starting from city 0 */
static int tsp_dp[1 << TSP_N][TSP_N];

static void tsp_solve(void) {
    int full = (1 << TSP_N);
    for (int m = 0; m < full; m++)
        for (int v = 0; v < TSP_N; v++)
            tsp_dp[m][v] = TSP_INF;

    tsp_dp[1][0] = 0;  /* start at city 0, mask = {0} */

    for (int mask = 1; mask < full; mask++) {
        for (int u = 0; u < TSP_N; u++) {
            if (!(mask & (1 << u))) continue;
            if (tsp_dp[mask][u] == TSP_INF) continue;
            for (int v = 0; v < TSP_N; v++) {
                if (mask & (1 << v)) continue;
                int nmask = mask | (1 << v);
                int ncost = tsp_dp[mask][u] + tsp_dist[u][v];
                if (ncost < tsp_dp[nmask][v])
                    tsp_dp[nmask][v] = ncost;
            }
        }
    }
}

void _start(void) {
    tsp_solve();

    int full_mask = (1 << TSP_N) - 1;
    int min_cost  = TSP_INF;
    for (int v = 1; v < TSP_N; v++) {
        int c = tsp_dp[full_mask][v] + tsp_dist[v][0];
        if (c < min_cost) min_cost = c;
    }
    /* min_cost = 80 */

    /* Count distinct non-zero off-diagonal distances (upper triangle): 6 */
    int n_edges = 0;
    for (int i = 0; i < TSP_N; i++)
        for (int j = i + 1; j < TSP_N; j++)
            if (tsp_dist[i][j] > 0) n_edges++;
    /* n_edges = 6 — but 6 repeats with nothing; use n_edges as low byte */
    /* bytes: TSP_N=4, min_cost=80=0x50, n_edges=6 → all distinct, all non-zero */

    g_result = ((uint32_t)TSP_N    << 16)
             | ((uint32_t)min_cost << 8)
             | (uint32_t)n_edges;
    while (1) {}
}
