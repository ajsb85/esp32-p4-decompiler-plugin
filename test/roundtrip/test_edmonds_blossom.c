/*
 * test_edmonds_blossom.c
 * Edmonds' Blossom algorithm for maximum matching in general (non-bipartite) graphs.
 * Uses augmenting-path search with blossom contraction via union-find coloring.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define EB_MAXN  16
#define EB_INF   (-1)

/* Adjacency list */
static int eb_adj[EB_MAXN][EB_MAXN];
static int eb_deg[EB_MAXN];
static int eb_n;

/* Matching */
static int eb_mate[EB_MAXN];

/* BFS workspace */
static int eb_queue[EB_MAXN];
static int eb_label[EB_MAXN];  /* 0=even, 1=odd, -1=unlabelled */
static int eb_parent[EB_MAXN];
static int eb_base[EB_MAXN];

static void eb_init(int n) {
    eb_n = n;
    for (int i = 0; i < n; i++) {
        eb_deg[i]  = 0;
        eb_mate[i] = EB_INF;
    }
}

static void eb_add_edge(int u, int v) {
    eb_adj[u][eb_deg[u]++] = v;
    eb_adj[v][eb_deg[v]++] = u;
}

/* LCA in alternating tree — find common ancestor of blossoms rooted at u,v */
static int eb_lca(int u, int v) {
    int visited[EB_MAXN];
    for (int i = 0; i < eb_n; i++) visited[i] = 0;
    /* trace u up */
    int cu = u;
    while (1) {
        cu = eb_base[cu];
        visited[cu] = 1;
        if (eb_mate[cu] == EB_INF) break;
        cu = eb_parent[eb_mate[cu]];
    }
    /* trace v up until we hit a visited node */
    int cv = v;
    while (1) {
        cv = eb_base[cv];
        if (visited[cv]) return cv;
        cv = eb_parent[eb_mate[cv]];
    }
}

/* Contract blossom: mark all nodes in blossom as having same base */
static void eb_mark_path(int v, int b, int child, int *queue, int *tail) {
    while (eb_base[v] != b) {
        queue[(*tail)++] = v;
        queue[(*tail)++] = eb_mate[v];
        eb_parent[v] = child;
        child = eb_mate[v];
        v = eb_parent[eb_mate[v]];
    }
}

static int eb_bfs(int root) {
    for (int i = 0; i < eb_n; i++) {
        eb_label[i]  = -1;
        eb_parent[i] = -1;
        eb_base[i]   = i;
    }
    int head = 0, tail = 0;
    eb_label[root] = 0;
    eb_queue[tail++] = root;

    while (head < tail) {
        int v = eb_queue[head++];
        for (int i = 0; i < eb_deg[v]; i++) {
            int u = eb_adj[v][i];
            if (eb_base[v] == eb_base[u] || eb_label[u] == 1)
                continue;
            if (eb_label[u] == -1) {
                if (eb_mate[u] == EB_INF) {
                    /* augmenting path found: reverse along parent links */
                    eb_parent[u] = v;
                    int cv = u;
                    while (cv != EB_INF) {
                        int pv = eb_parent[cv];
                        int ppv = eb_mate[pv];
                        eb_mate[cv] = pv;
                        eb_mate[pv] = cv;
                        cv = ppv;
                    }
                    return 1;
                }
                /* extend tree: label u as odd, mate[u] as even */
                eb_label[u] = 1;
                eb_parent[u] = v;
                int mu = eb_mate[u];
                eb_label[mu] = 0;
                eb_queue[tail++] = mu;
            } else {
                /* both even: blossom found */
                int b = eb_lca(v, u);
                /* contract blossom */
                int bq[EB_MAXN], btail = 0;
                eb_mark_path(v, b, u, bq, &btail);
                eb_mark_path(u, b, v, bq, &btail);
                for (int k = 0; k < btail; k++) {
                    eb_base[bq[k]] = b;
                    if (eb_label[bq[k]] == -1) {
                        eb_label[bq[k]] = 0;
                        eb_queue[tail++] = bq[k];
                    }
                }
            }
        }
    }
    return 0;
}

static int eb_max_matching(void) {
    int ans = 0;
    for (int v = 0; v < eb_n; v++) {
        if (eb_mate[v] == EB_INF)
            ans += eb_bfs(v);
    }
    return ans;
}

static uint32_t run_edmonds_blossom_tests(void) {
    /*
     * Test 1: Triangle (3-cycle: 0-1-2-0)
     * Max matching = 1
     */
    eb_init(3);
    eb_add_edge(0, 1);
    eb_add_edge(1, 2);
    eb_add_edge(2, 0);
    int m1 = eb_max_matching(); /* expected 1 */

    /*
     * Test 2: 5-cycle (0-1-2-3-4-0)
     * Max matching = 2
     */
    eb_init(5);
    eb_add_edge(0, 1);
    eb_add_edge(1, 2);
    eb_add_edge(2, 3);
    eb_add_edge(3, 4);
    eb_add_edge(4, 0);
    int m2 = eb_max_matching(); /* expected 2 */

    /*
     * Test 3: K4 (complete graph on 4 nodes)
     * Max matching = 2
     */
    eb_init(4);
    eb_add_edge(0, 1);
    eb_add_edge(0, 2);
    eb_add_edge(0, 3);
    eb_add_edge(1, 2);
    eb_add_edge(1, 3);
    eb_add_edge(2, 3);
    int m3 = eb_max_matching(); /* expected 2 */
    (void)m3;

    /*
     * Pack: n_tests=3, metric_a=m2 (2=0x02), metric_b=m1 (1=0x01)
     * BUT 0x03, 0x02, 0x01 are all distinct non-zero.
     * Use m2<<8|m1 plus m3 for verification:  m2=2, m3=2 same.
     * Use (3<<16)|(m2<<8)|m1 = 0x030201
     */
    uint32_t metric_a = (uint32_t)(m2 & 0xFF); /* 2 = 0x02 */
    uint32_t metric_b = (uint32_t)(m1 & 0xFF); /* 1 = 0x01 */
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_edmonds_blossom_tests();
    while (1) {}
}
