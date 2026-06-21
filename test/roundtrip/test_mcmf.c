/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Min-Cost Max-Flow (SPFA) fixture.
 *
 * Finds the maximum flow with minimum total cost using SPFA to find
 * shortest (min-cost) augmenting paths in the residual graph.
 *
 * Distinctive decompiler idioms:
 *   1. `mc_e[mc_ec]={v,c,w,mc_hd[u]}; mc_hd[u]=mc_ec++` — linked edge list
 *   2. `mc_e[mc_ec]={u,0,-w,mc_hd[v]}; mc_hd[v]=mc_ec++` — reverse edge (cost=-w)
 *   3. `e^1` — XOR-based reverse edge index (pairs are at even+odd addresses)
 *   4. `if(mc_e[i].cap>0 && mc_d[u]+mc_e[i].cost < mc_d[v])` — relax with capacity
 *   5. `while(hd!=tl){u=q[hd++]; ...}` — SPFA BFS with in-queue guard
 *   6. `mc_e[e].cap-=f; mc_e[e^1].cap+=f` — augment: reduce forward, increase backward
 *
 * Graph (n=4, s=0, t=3):
 *   (0→1, cap=2, cost=1), (0→2, cap=3, cost=2)
 *   (1→3, cap=1, cost=4), (2→3, cap=2, cost=1)
 *   (1→2, cap=1, cost=1)
 *
 * Min-cost max-flow paths:
 *   Path 1: 0→1→2→3, cost=3, flow=1 → cumulative cost=3
 *   Path 2: 0→2→3,   cost=3, flow=1 → cumulative cost=6
 *   Path 3: 0→1→3,   cost=5, flow=1 → cumulative cost=11
 *   (Max flow=3 limited by sink capacity 1+2=3)
 *
 * n_nodes  = 4  = 0x04
 * max_flow = 3  = 0x03
 * min_cost = 11 = 0x0B
 *
 * g_result = (n_nodes << 16) | (max_flow << 8) | min_cost = 0x04030B
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MC_N   4
#define MC_ME  16   /* 2x number of edges (forward+backward) */

typedef struct { int to, cap, cost, nxt; } McEdge;
static McEdge mc_e[MC_ME];
static int    mc_hd[MC_N];
static int    mc_ec;

static void mc_init(void)
{
    for (int i = 0; i < MC_N; i++) mc_hd[i] = -1;
    mc_ec = 0;
}

static void mc_add(int u, int v, int cap, int cost)
{
    mc_e[mc_ec] = (McEdge){ v, cap,  cost, mc_hd[u] }; mc_hd[u] = mc_ec++;
    mc_e[mc_ec] = (McEdge){ u,   0, -cost, mc_hd[v] }; mc_hd[v] = mc_ec++;
}

#define MC_INF 0x7FFFFFFF
static int mc_d[MC_N], mc_inq[MC_N], mc_pe[MC_N];

static int mc_spfa(int s, int t, int *path_cap)
{
    for (int i = 0; i < MC_N; i++) { mc_d[i] = MC_INF; mc_inq[i] = 0; }
    mc_d[s] = 0; mc_inq[s] = 1;
    int q[64], hd = 0, tl = 0;
    q[tl++] = s;
    while (hd != tl) {
        int u = q[hd++]; mc_inq[u] = 0;
        for (int i = mc_hd[u]; i != -1; i = mc_e[i].nxt) {
            int v = mc_e[i].to;
            if (mc_e[i].cap > 0 && mc_d[u] + mc_e[i].cost < mc_d[v]) {
                mc_d[v] = mc_d[u] + mc_e[i].cost;
                mc_pe[v] = i;
                if (!mc_inq[v]) { mc_inq[v] = 1; q[tl++] = v; }
            }
        }
    }
    if (mc_d[t] == MC_INF) return 0;
    *path_cap = MC_INF;
    for (int v = t; v != s; ) {
        int e = mc_pe[v];
        if (mc_e[e].cap < *path_cap) *path_cap = mc_e[e].cap;
        v = mc_e[e ^ 1].to;
    }
    return mc_d[t];
}

static void mc_aug(int s, int t, int flow)
{
    for (int v = t; v != s; ) {
        int e = mc_pe[v];
        mc_e[e].cap     -= flow;
        mc_e[e ^ 1].cap += flow;
        v = mc_e[e ^ 1].to;
    }
}

void test_mcmf(void)
{
    mc_init();
    mc_add(0, 1, 2, 1);
    mc_add(0, 2, 3, 2);
    mc_add(1, 3, 1, 4);
    mc_add(2, 3, 2, 1);
    mc_add(1, 2, 1, 1);

    int flow = 0, cost = 0, pcap, c;
    while ((c = mc_spfa(0, 3, &pcap)) > 0) {
        mc_aug(0, 3, pcap);
        flow += pcap;
        cost += c * pcap;
    }
    /* flow=3, cost=11 */

    g_result = ((uint32_t)MC_N  << 16)
             | ((uint32_t)flow  << 8)
             | ((uint32_t)cost & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_mcmf();
    for (;;);
}
