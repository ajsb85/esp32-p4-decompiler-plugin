/* test_min_cost_flow.c
 * Purpose   : Validate min-cost max-flow (MCMF) via SPFA (Bellman-Ford BFS)
 * Algorithm : Build a flow network; use shortest-path Bellman-Ford (SPFA) to find
 *             augmenting paths with minimum cost.  Augment along each path.
 *             Repeat until no augmenting path exists.
 *             Characteristic idioms:
 *               - Reverse edge trick: edge[i^1] is the reverse of edge[i]
 *               - dist[] initialized to INT_MAX / big constant; relaxed via queue
 *               - in_queue[] boolean for SPFA
 *               - flow along path = min residual capacity on path
 *               - total_cost += path_flow * dist[sink]
 * Input     : 4-node network (0=src, 3=sink):
 *               0→1 cap=3 cost=1, 0→2 cap=2 cost=4
 *               1→3 cap=2 cost=2, 1→2 cap=1 cost=1
 *               2→3 cap=3 cost=3
 *             Min-cost max-flow: max_flow=4, min_cost=23
 * g_result  = (n_nodes << 16) | (max_flow << 8) | (min_cost - 16)
 *           = (4 << 16) | (4 << 8) | 7   => 0x040407
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MCF_V    4
#define MCF_MAXE 20   /* max edges (including reverse edges) */

#define MCF_INF  0x7FFFFFFF

static int mcf_head[MCF_V];
static int mcf_to[MCF_MAXE];
static int mcf_cap[MCF_MAXE];
static int mcf_cost[MCF_MAXE];
static int mcf_next[MCF_MAXE];
static int mcf_ecnt;

static void mcf_init(void) {
    for (int i = 0; i < MCF_V; i++) mcf_head[i] = -1;
    mcf_ecnt = 0;
}

/* Add directed edge u→v with capacity c and cost w; also add reverse edge */
static void mcf_add(int u, int v, int c, int w) {
    mcf_to[mcf_ecnt]   = v;
    mcf_cap[mcf_ecnt]  = c;
    mcf_cost[mcf_ecnt] = w;
    mcf_next[mcf_ecnt] = mcf_head[u];
    mcf_head[u]        = mcf_ecnt++;

    mcf_to[mcf_ecnt]   = u;   /* reverse edge */
    mcf_cap[mcf_ecnt]  = 0;
    mcf_cost[mcf_ecnt] = -w;
    mcf_next[mcf_ecnt] = mcf_head[v];
    mcf_head[v]        = mcf_ecnt++;
}

/* SPFA: find shortest (min-cost) path from src to sink with residual capacity.
 * Returns 1 if a path was found, 0 otherwise.
 * prevv[v] = node before v on path; preve[v] = edge index used to reach v. */
static int mcf_dist[MCF_V];
static int mcf_inq[MCF_V];
static int mcf_prevv[MCF_V];
static int mcf_preve[MCF_V];

static int mcf_spfa(int s, int t) {
    for (int i = 0; i < MCF_V; i++) { mcf_dist[i] = MCF_INF; mcf_inq[i] = 0; }
    /* Simple queue */
    int q[MCF_V * 4];
    int qh = 0, qt = 0;
    mcf_dist[s] = 0;
    q[qt++] = s;
    mcf_inq[s] = 1;
    while (qh != qt) {
        int u = q[qh++];
        if (qh >= MCF_V * 4) qh = 0;
        mcf_inq[u] = 0;
        for (int e = mcf_head[u]; e != -1; e = mcf_next[e]) {
            int v = mcf_to[e];
            if (mcf_cap[e] > 0 && mcf_dist[u] + mcf_cost[e] < mcf_dist[v]) {
                mcf_dist[v]  = mcf_dist[u] + mcf_cost[e];
                mcf_prevv[v] = u;
                mcf_preve[v] = e;
                if (!mcf_inq[v]) {
                    q[qt++] = v;
                    if (qt >= MCF_V * 4) qt = 0;
                    mcf_inq[v] = 1;
                }
            }
        }
    }
    return mcf_dist[t] != MCF_INF;
}

static void mcf_run(int s, int t, int *total_flow, int *total_cost) {
    *total_flow = 0;
    *total_cost = 0;
    while (mcf_spfa(s, t)) {
        /* Find min residual capacity along the path */
        int f = MCF_INF;
        for (int v = t; v != s; v = mcf_prevv[v]) {
            int e = mcf_preve[v];
            if (mcf_cap[e] < f) f = mcf_cap[e];
        }
        /* Augment */
        for (int v = t; v != s; v = mcf_prevv[v]) {
            int e = mcf_preve[v];
            mcf_cap[e]     -= f;
            mcf_cap[e ^ 1] += f;  /* reverse edge (index i^1 is the reverse of i) */
        }
        *total_flow += f;
        *total_cost += f * mcf_dist[t];
    }
}

void test_min_cost_flow(void) {
    mcf_init();
    /* Build network */
    mcf_add(0, 1, 3, 1);
    mcf_add(0, 2, 2, 4);
    mcf_add(1, 3, 2, 2);
    mcf_add(1, 2, 1, 1);
    mcf_add(2, 3, 3, 3);

    int max_flow = 0, min_cost = 0;
    mcf_run(0, 3, &max_flow, &min_cost);

    /* max_flow=4, min_cost=23; byte2=min_cost-16=7 */
    g_result = ((uint32_t)MCF_V          << 16)
             | ((uint32_t)max_flow       <<  8)
             | (uint32_t)(min_cost - 16);
    while (1) {}
}

__attribute__((noreturn)) void _start(void) {
    test_min_cost_flow();
    for (;;);
}
