/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Articulation Points (Tarjan, undirected) fixture.
 *
 * Finds cut vertices (articulation points) in an undirected graph using DFS
 * with discovery time (disc[]) and low-link value (low[]).
 *
 * Distinctive decompiler idioms:
 *   1. `disc[u] = low[u] = timer++` — assign discovery time and low simultaneously
 *   2. `if(!vis[v]) { child_cnt++; par[v]=u; dfs(v); low[u]=min(low[u],low[v]); }` — tree edge
 *   3. `else if(v!=par[u]) low[u]=min(low[u],disc[v])` — back edge (skip parent)
 *   4. Root AP: `par[u]==-1 && child_cnt>1` — root with multiple DFS children
 *   5. Non-root AP: `par[u]!=-1 && low[v]>=disc[u]` — cannot bypass u via back edge
 *
 * Graph (5 nodes, undirected):
 *   Edges: 0–1, 1–2, 2–0, 1–3, 3–4
 *   Triangle {0,1,2}, then chain 1–3–4.
 *   APs: node 1 (separates triangle from chain) and node 3 (separates 4).
 *
 * n         = 5
 * ap_count  = 2
 * ap_xor    = 1^3 = 2
 *
 * g_result = (5 << 16) | (ap_count << 8) | ap_xor = 0x00050202
 */
#include <stdint.h>

volatile uint32_t g_result;

#define AP_N  5
#define AP_NE 5

static const int ap_edges[AP_NE][2] = {
    {0,1}, {1,2}, {2,0}, {1,3}, {3,4}
};

static int ap_adj[AP_N][4];
static int ap_deg[AP_N];
static int ap_disc[AP_N];
static int ap_low[AP_N];
static int ap_vis[AP_N];
static int ap_par[AP_N];
static int ap_is_ap[AP_N];
static int ap_timer;

static void ap_dfs(int u)
{
    ap_disc[u] = ap_low[u] = ap_timer++;
    ap_vis[u] = 1;
    int child_cnt = 0;
    for (int i = 0; i < ap_deg[u]; i++) {
        int v = ap_adj[u][i];
        if (!ap_vis[v]) {
            child_cnt++;
            ap_par[v] = u;
            ap_dfs(v);
            if (ap_low[v] < ap_low[u]) ap_low[u] = ap_low[v];
            if (ap_par[u] == -1 && child_cnt > 1) ap_is_ap[u] = 1;
            if (ap_par[u] != -1 && ap_low[v] >= ap_disc[u]) ap_is_ap[u] = 1;
        } else if (v != ap_par[u]) {
            if (ap_disc[v] < ap_low[u]) ap_low[u] = ap_disc[v];
        }
    }
}

void test_articulation(void)
{
    for (int i = 0; i < AP_N; i++) {
        ap_vis[i] = ap_is_ap[i] = ap_deg[i] = 0;
        ap_par[i] = -1;
    }
    ap_timer = 0;

    /* build undirected adjacency */
    for (int i = 0; i < AP_NE; i++) {
        int u = ap_edges[i][0], v = ap_edges[i][1];
        ap_adj[u][ap_deg[u]++] = v;
        ap_adj[v][ap_deg[v]++] = u;
    }

    ap_dfs(0);

    uint32_t ap_count = 0, ap_xor = 0;
    for (int i = 0; i < AP_N; i++) {
        if (ap_is_ap[i]) { ap_count++; ap_xor ^= (uint32_t)i; }
    }

    /* ap_count=2, ap_xor=2 */
    g_result = ((uint32_t)AP_N << 16) | ((ap_count & 0xFFu) << 8) | (ap_xor & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_articulation();
    for (;;);
}
