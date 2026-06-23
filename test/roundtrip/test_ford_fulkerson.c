/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Ford-Fulkerson Max-Flow (DFS augmenting paths).
 *
 * Ford-Fulkerson finds max-flow by repeatedly searching for an augmenting path
 * from source to sink in the residual graph (DFS variant, O(E * maxflow)).
 *
 * Distinctive decompiler idioms:
 *   1. residual[u][v] > 0 guard before DFS neighbour visit
 *   2. visited[v] = 1 before recursive call (cycle prevention)
 *   3. min(path_flow, residual[u][v]) — bottleneck computation
 *   4. residual[u][v] -= flow; residual[v][u] += flow — residual update pair
 *   5. while (dfs(src, sink, INF) > 0) total_flow += ... — outer loop
 *
 * Graph (6 nodes, 0=source, 5=sink):
 *   0→1 cap=16, 0→2 cap=13
 *   1→2 cap=10, 1→3 cap=12
 *   2→1 cap=4,  2→4 cap=14
 *   3→2 cap=9,  3→5 cap=20
 *   4→3 cap=7,  4→5 cap=4
 *
 * Max flow (standard benchmark): 23
 * g_result = 23 = 0x17 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FF_N   6
#define FF_INF 0x7FFFFFFF

static int ff_res[FF_N][FF_N];
static int ff_vis[FF_N];

static int ff_dfs(int u, int t, int pushed) {
    if (u == t) return pushed;
    ff_vis[u] = 1;
    for (int v = 0; v < FF_N; v++) {
        if (!ff_vis[v] && ff_res[u][v] > 0) {
            int d = (pushed < ff_res[u][v]) ? pushed : ff_res[u][v];
            int flow = ff_dfs(v, t, d);
            if (flow > 0) {
                ff_res[u][v] -= flow;
                ff_res[v][u] += flow;
                return flow;
            }
        }
    }
    return 0;
}

static int ff_maxflow(int s, int t) {
    int total = 0;
    int f;
    do {
        for (int i = 0; i < FF_N; i++) ff_vis[i] = 0;
        f = ff_dfs(s, t, FF_INF);
        total += f;
    } while (f > 0);
    return total;
}

void test_ford_fulkerson(void)
{
    ff_res[0][1] = 16; ff_res[0][2] = 13;
    ff_res[1][2] = 10; ff_res[1][3] = 12;
    ff_res[2][1] =  4; ff_res[2][4] = 14;
    ff_res[3][2] =  9; ff_res[3][5] = 20;
    ff_res[4][3] =  7; ff_res[4][5] =  4;

    int mf = ff_maxflow(0, 5);  /* expected: 23 */
    g_result = (uint32_t)mf;
}

__attribute__((noreturn)) void _start(void)
{
    test_ford_fulkerson();
    for (;;);
}
