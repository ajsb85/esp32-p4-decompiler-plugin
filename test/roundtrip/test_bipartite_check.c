/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Bipartite Graph Check (BFS 2-coloring) fixture.
 *
 * Determines if a graph is bipartite (2-colorable) using BFS:
 * assign alternating colors 1/2 to nodes during traversal.
 * If a neighbor has the same color as the current node: not bipartite.
 *
 * Distinctive decompiler idioms:
 *   1. Color array with 3 states: 0=unvisited, 1=color1, 2=color2
 *   2. `color[v] = 3 - color[u]` — color-swap without branch
 *   3. `if (color[v] == color[u]) return 0` — conflict detection
 *   4. Outer loop for disconnected components: `for (src=0; src<n; src++)`
 *
 * Three test graphs:
 *   1. Triangle  {0-1, 1-2, 0-2}              n=3 → NOT bipartite (odd cycle)
 *   2. Square    {0-1, 1-2, 2-3, 0-3}         n=4 → bipartite (even cycle)
 *   3. Pentagon  {0-1, 1-2, 2-3, 3-4, 4-0}    n=5 → NOT bipartite (odd cycle)
 *
 * n_tests         = 3
 * count_bipartite = 1   (only graph 2)
 * xor_results     = 0^1^0 = 1
 *
 * g_result = (n_tests << 16) | (count_bipartite << 8) | xor_results = 0x00030101
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Bipartite Check ─────────────────────────────────────────────────────── */

#define BP_TESTS 3
#define BP_MAXN  5

static int bp_color[BP_MAXN];
static int bp_q[BP_MAXN];

static int is_bipartite(const int adj[][BP_MAXN], const int deg[], int n)
{
    for (int i = 0; i < n; i++) bp_color[i] = 0;
    for (int src = 0; src < n; src++) {
        if (bp_color[src]) continue;
        bp_color[src] = 1;
        int front = 0, back = 0;
        bp_q[back++] = src;
        while (front < back) {
            int u = bp_q[front++];
            for (int i = 0; i < deg[u]; i++) {
                int v = adj[u][i];
                if (!bp_color[v]) {
                    bp_color[v] = 3 - bp_color[u];
                    bp_q[back++] = v;
                } else if (bp_color[v] == bp_color[u]) {
                    return 0;
                }
            }
        }
    }
    return 1;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_bipartite_check(void)
{
    /* Graph 1: triangle 0-1, 1-2, 0-2 (NOT bipartite) */
    static const int adj1[3][BP_MAXN] = {{1,2},{0,2},{0,1}};
    static const int deg1[3] = {2,2,2};

    /* Graph 2: square 0-1, 1-2, 2-3, 3-0 (bipartite) */
    static const int adj2[4][BP_MAXN] = {{1,3},{0,2},{1,3},{2,0}};
    static const int deg2[4] = {2,2,2,2};

    /* Graph 3: pentagon 0-1, 1-2, 2-3, 3-4, 4-0 (NOT bipartite) */
    static const int adj3[5][BP_MAXN] = {{1,4},{0,2},{1,3},{2,4},{3,0}};
    static const int deg3[5] = {2,2,2,2,2};

    int r0 = is_bipartite(adj1, deg1, 3);
    int r1 = is_bipartite(adj2, deg2, 4);
    int r2 = is_bipartite(adj3, deg3, 5);

    uint32_t count_b = (uint32_t)(r0 + r1 + r2);
    uint32_t xor_res = (uint32_t)(r0 ^ r1 ^ r2);
    /* count=1 (r1 only), xor=0^1^0=1 */

    g_result = ((uint32_t)BP_TESTS << 16) | (count_b << 8) | (xor_res & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_bipartite_check();
    for (;;);
}
