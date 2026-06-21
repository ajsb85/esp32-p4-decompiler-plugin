/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — TSP via Bitmask DP fixture.
 *
 * Travelling Salesman Problem on n=4 cities using held-karp bitmask DP:
 *   dp[mask][i] = min cost to visit exactly the cities in `mask`, ending at i.
 *
 * Distinctive decompiler idioms:
 *   1. `dp[1 << 0][0] = 0` — start at city 0 with only city 0 visited
 *   2. `if (!(mask & (1 << i))) continue` — i must be in mask
 *   3. `dp[mask | (1 << j)][j] = min(dp[mask|(1<<j)][j], dp[mask][i]+cost[i][j])`
 *   4. `min over i: dp[(1<<n)-1][i] + cost[i][0]` — close the tour
 *
 * Distance matrix (symmetric):
 *   cost[0][1]=10, cost[0][2]=15, cost[0][3]=20
 *   cost[1][2]=35, cost[1][3]=25
 *   cost[2][3]=30
 *
 * Optimal tours and their costs:
 *   0→1→3→2→0 = 10+25+30+15 = 80  ← minimum
 *   0→2→3→1→0 = 15+30+25+10 = 80
 *   0→1→2→3→0 = 10+35+30+20 = 95
 *
 * n_cities  = 4
 * min_cost  = 80 (0x50)
 * xor_last  = n_cities = 4
 *
 * g_result = (n_cities << 16) | (min_cost << 8) | n_cities = 0x00045004
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── TSP bitmask DP ──────────────────────────────────────────────────────── */

#define TSP_N   4
#define TSP_INF 999999

static const int tsp_cost[TSP_N][TSP_N] = {
    {0,  10, 15, 20},
    {10,  0, 35, 25},
    {15, 35,  0, 30},
    {20, 25, 30,  0}
};

static int tsp_dp[1 << TSP_N][TSP_N];

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_tsp_bitmask(void)
{
    for (int m = 0; m < (1 << TSP_N); m++)
        for (int i = 0; i < TSP_N; i++)
            tsp_dp[m][i] = TSP_INF;

    tsp_dp[1][0] = 0; /* start at city 0, mask = {0} */

    for (int mask = 1; mask < (1 << TSP_N); mask++) {
        for (int i = 0; i < TSP_N; i++) {
            if (!(mask & (1 << i))) continue;
            if (tsp_dp[mask][i] == TSP_INF) continue;
            for (int j = 0; j < TSP_N; j++) {
                if (mask & (1 << j)) continue;
                int nm = mask | (1 << j);
                int nc = tsp_dp[mask][i] + tsp_cost[i][j];
                if (nc < tsp_dp[nm][j]) tsp_dp[nm][j] = nc;
            }
        }
    }

    int all = (1 << TSP_N) - 1;
    int best = TSP_INF;
    for (int i = 1; i < TSP_N; i++) {
        int c = tsp_dp[all][i] + tsp_cost[i][0];
        if (c < best) best = c;
    }

    /* best=80, n=4 */
    g_result = ((uint32_t)TSP_N << 16)
             | ((uint32_t)(best & 0xFF) << 8)
             | (uint32_t)TSP_N;
}

__attribute__((noreturn)) void _start(void)
{
    test_tsp_bitmask();
    for (;;);
}
