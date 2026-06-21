/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Tarjan Bridge Finding fixture.
 *
 * An edge (u,v) is a bridge if removing it disconnects the graph.
 * Tarjan's bridge algorithm uses DFS timestamps and low-link values:
 *   low[v] = min(disc[v], min(disc[w]) for back-edges (v,w), min(low[child]) for tree edges)
 *
 * Bridge condition: low[v] > disc[u]  (strict inequality — no back-edge reaches u or above)
 *   NOTE: This differs from articulation point: low[v] >= disc[u] (non-strict)
 *
 * Distinctive decompiler idioms:
 *   1. `if (v == parent) continue` — skip tree parent edge
 *   2. `low[u] = min(low[u], disc[v])` — back-edge low update
 *   3. `if (low[v] > disc[u]) n_bridges++` — bridge detection (strict >)
 *   4. Timer increment: `disc[v] = low[v] = ++br_timer`
 *
 * Graph: path 0-1-2-3-4 (n=5, no back-edges → all 4 edges are bridges)
 *   0──1──2──3──4
 *
 * Verify: low[v] = disc[v] for all v (no back-edges to exploit)
 *   low[1]=disc[1]>disc[0] → bridge; low[2]>disc[1] → bridge; ...
 *
 * n_nodes    = 5  = 0x05
 * n_bridges  = 4  = 0x04
 * sum_uv     = (0+1)+(1+2)+(2+3)+(3+4) = 1+3+5+7 = 16 → truncated to 0x10=16
 *   or simpler: sum of smaller endpoints = 0+1+2+3 = 6 = 0x06
 *
 * g_result = (n_nodes << 16) | (n_bridges << 8) | sum_u = 0x050406
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BR_N 5

static int br_adj[BR_N][BR_N];
static int br_disc[BR_N];
static int br_low[BR_N];
static int br_visited[BR_N];
static int br_timer;
static int br_n_bridges;
static int br_sum_u;  /* sum of smaller endpoints of bridges */

static void br_dfs(int u, int parent)
{
    br_disc[u] = br_low[u] = ++br_timer;
    br_visited[u] = 1;

    for (int v = 0; v < BR_N; v++) {
        if (!br_adj[u][v]) continue;
        if (!br_visited[v]) {
            br_dfs(v, u);
            if (br_low[v] < br_low[u]) br_low[u] = br_low[v];
            if (br_low[v] > br_disc[u]) {
                br_n_bridges++;
                br_sum_u += (u < v ? u : v);
            }
        } else if (v != parent) {
            if (br_disc[v] < br_low[u]) br_low[u] = br_disc[v];
        }
    }
}

void test_bridges(void)
{
    /* Path: 0-1-2-3-4 */
    static const int edges[][2] = {{0,1},{1,2},{2,3},{3,4}};
    for (int i = 0; i < 4; i++) {
        int u = edges[i][0], v = edges[i][1];
        br_adj[u][v] = br_adj[v][u] = 1;
    }

    br_dfs(0, -1);
    /* n_bridges=4, sum_u=0+1+2+3=6 */

    g_result = ((uint32_t)BR_N          << 16)
             | ((uint32_t)br_n_bridges  << 8)
             | ((uint32_t)br_sum_u & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_bridges();
    for (;;);
}
