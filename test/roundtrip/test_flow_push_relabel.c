/* test_flow_push_relabel.c — Push-Relabel max-flow (highest-label variant)
 * Self-contained, no system includes except <stdint.h>.
 * Compiles with:
 *   riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f \
 *     -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_flow_push_relabel.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── push-relabel constants ──────────────────────────────────────────────── */
#define PR_MAXV   8
#define PR_MAXE   64   /* directed edges (each undirected edge = 2 slots) */

typedef struct PrEdge {
    int32_t to, cap, flow, rev;
} PrEdge;

static PrEdge pr_edges[PR_MAXE];
static int32_t pr_head[PR_MAXV];   /* adjacency list heads */
static int32_t pr_next[PR_MAXE];   /* next edge in adj list */
static int32_t pr_ne;              /* total edge count */

static int32_t pr_height[PR_MAXV];
static int64_t pr_excess[PR_MAXV];
static int32_t pr_cur[PR_MAXV];    /* current edge pointer per node */

static int32_t pr_n;               /* number of vertices */
static int32_t pr_S, pr_T;        /* source, sink */

static void pr_init(int32_t n, int32_t s, int32_t t) {
    int32_t i;
    pr_n = n; pr_S = s; pr_T = t; pr_ne = 0;
    for (i = 0; i < n; i++) {
        pr_head[i]   = -1;
        pr_height[i] = 0;
        pr_excess[i] = 0;
    }
}

static void pr_add_edge(int32_t u, int32_t v, int32_t cap) {
    /* forward edge */
    pr_edges[pr_ne].to   = v;
    pr_edges[pr_ne].cap  = cap;
    pr_edges[pr_ne].flow = 0;
    pr_edges[pr_ne].rev  = pr_ne + 1;
    pr_next[pr_ne]       = pr_head[u];
    pr_head[u]           = pr_ne++;
    /* backward edge */
    pr_edges[pr_ne].to   = u;
    pr_edges[pr_ne].cap  = 0;
    pr_edges[pr_ne].flow = 0;
    pr_edges[pr_ne].rev  = pr_ne - 1;
    pr_next[pr_ne]       = pr_head[v];
    pr_head[v]           = pr_ne++;
}

/* simple BFS to compute initial heights from sink */
static int32_t pr_bfs_queue[PR_MAXV];

static void pr_bfs_height(void) {
    int32_t i;
    for (i = 0; i < pr_n; i++) pr_height[i] = pr_n;
    pr_height[pr_T] = 0;
    int32_t front = 0, back = 0;
    pr_bfs_queue[back++] = pr_T;
    while (front < back) {
        int32_t u = pr_bfs_queue[front++];
        int32_t e;
        for (e = pr_head[u]; e >= 0; e = pr_next[e]) {
            int32_t rev = pr_edges[e].rev;
            int32_t v   = pr_edges[rev].to; /* neighbour of u via reverse */
            /* reverse edge carries residual cap if original has flow */
            if (pr_height[v] > pr_height[u] + 1 &&
                pr_edges[rev].cap - pr_edges[rev].flow > 0) {
                pr_height[v] = pr_height[u] + 1;
                pr_bfs_queue[back++] = v;
            }
        }
    }
    /* re-BFS properly: from T on *reverse* residual */
    for (i = 0; i < pr_n; i++) pr_height[i] = pr_n;
    pr_height[pr_T] = 0;
    front = back = 0;
    pr_bfs_queue[back++] = pr_T;
    while (front < back) {
        int32_t u = pr_bfs_queue[front++];
        int32_t e;
        for (e = pr_head[u]; e >= 0; e = pr_next[e]) {
            int32_t v = pr_edges[e].to;
            /* only traverse edges that have capacity in the *reverse* direction */
            int32_t rev = pr_edges[e].rev;
            if (pr_height[v] > pr_height[u] + 1 &&
                pr_edges[rev].cap - pr_edges[rev].flow > 0) {
                pr_height[v] = pr_height[u] + 1;
                pr_bfs_queue[back++] = v;
            }
        }
    }
    pr_height[pr_S] = pr_n;
}

static void pr_push(int32_t u, int32_t e) {
    int32_t v    = pr_edges[e].to;
    int64_t res  = (int64_t)(pr_edges[e].cap - pr_edges[e].flow);
    int64_t send = pr_excess[u] < res ? pr_excess[u] : res;
    pr_edges[e].flow                += (int32_t)send;
    pr_edges[pr_edges[e].rev].flow  -= (int32_t)send;
    pr_excess[u] -= send;
    pr_excess[v] += send;
}

static void pr_relabel(int32_t u) {
    int32_t min_h = 2 * pr_n;
    int32_t e;
    for (e = pr_head[u]; e >= 0; e = pr_next[e]) {
        if (pr_edges[e].cap - pr_edges[e].flow > 0) {
            int32_t v = pr_edges[e].to;
            if (pr_height[v] < min_h) min_h = pr_height[v];
        }
    }
    pr_height[u] = min_h + 1;
}

static int64_t pr_max_flow(void) {
    int32_t i, e;
    pr_bfs_height();
    /* set source height to n */
    pr_height[pr_S] = pr_n;
    /* initialise current edge pointers */
    for (i = 0; i < pr_n; i++) pr_cur[i] = pr_head[i];
    /* saturate all edges out of source */
    for (e = pr_head[pr_S]; e >= 0; e = pr_next[e]) {
        int32_t res = pr_edges[e].cap - pr_edges[e].flow;
        if (res > 0) {
            int32_t v = pr_edges[e].to;
            pr_edges[e].flow += res;
            pr_edges[pr_edges[e].rev].flow -= res;
            pr_excess[pr_S] -= res;
            pr_excess[v]    += res;
        }
    }
    /* main loop: process active nodes (excess > 0, not S or T) */
    int32_t changed = 1;
    while (changed) {
        changed = 0;
        for (i = 0; i < pr_n; i++) {
            if (i == pr_S || i == pr_T) continue;
            if (pr_excess[i] <= 0) continue;
            changed = 1;
            /* try to push */
            int32_t pushed = 0;
            for (e = pr_cur[i]; e >= 0; e = pr_next[e]) {
                int32_t v   = pr_edges[e].to;
                int32_t res = pr_edges[e].cap - pr_edges[e].flow;
                if (res > 0 && pr_height[v] == pr_height[i] - 1) {
                    pr_push(i, e);
                    pr_cur[i] = e;
                    pushed = 1;
                    if (pr_excess[i] == 0) break;
                }
            }
            if (!pushed) {
                /* relabel */
                pr_relabel(i);
                pr_cur[i] = pr_head[i];
            }
        }
    }
    return pr_excess[pr_T];
}

/* ── test driver ─────────────────────────────────────────────────────────── */
static void run_flow_push_relabel_test(void) {
    /*
     * Classic 6-node flow network (0=S, 5=T):
     *   0->1: 16,  0->2: 13
     *   1->2: 10,  1->3: 12
     *   2->1: 4,   2->4: 14
     *   3->2: 9,   3->5: 20
     *   4->3: 7,   4->5: 4
     * Expected max flow = 23
     */
    pr_init(6, 0, 5);
    pr_add_edge(0, 1, 16);
    pr_add_edge(0, 2, 13);
    pr_add_edge(1, 2, 10);
    pr_add_edge(1, 3, 12);
    pr_add_edge(2, 1, 4);
    pr_add_edge(2, 4, 14);
    pr_add_edge(3, 2, 9);
    pr_add_edge(3, 5, 20);
    pr_add_edge(4, 3, 7);
    pr_add_edge(4, 5, 4);

    int64_t mf = pr_max_flow();

    uint32_t n_tests  = 10u;  /* 10 edges */
    uint32_t metric_a = (uint32_t)(mf & 0xFFu);
    if (metric_a == 0) metric_a = 0x01u;
    uint32_t metric_b = (uint32_t)((mf >> 3) & 0xFFu) | 0x04u;
    if (metric_b == metric_a) metric_b ^= 0x40u;
    if (metric_b == 0) metric_b = 0x05u;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    run_flow_push_relabel_test();
    while (1) {}
}
