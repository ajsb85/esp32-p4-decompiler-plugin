/* test_offline_lca_tarjan.c
 * Tarjan's offline LCA algorithm using union-find (DSU).
 * Processes a small rooted tree (N=8 nodes) and answers M=6 LCA queries
 * in one DFS pass.
 *
 * g_result = (n_tests << 16) | (metric_a << 8) | metric_b
 *   n_tests  = 6   (number of LCA queries)
 *   metric_a = sum of LCA answers (node ids) mod 256
 *   metric_b = XOR of LCA answers mod 256
 */

typedef unsigned int uint32_t;

extern volatile unsigned g_result;

/* ── DSU (union-find) ─────────────────────────────────────────────── */

#define MAXN 10

static int dsu_parent[MAXN];

static int dsu_find(int x)
{
    while (dsu_parent[x] != x)
        x = dsu_parent[x] = dsu_parent[dsu_parent[x]]; /* path-split */
    return x;
}

static void dsu_union(int a, int b)
{
    a = dsu_find(a);
    b = dsu_find(b);
    if (a != b) dsu_parent[a] = b;
}

/* ── Tree & queries ───────────────────────────────────────────────── */

/*
 * Tree (1-indexed, N=8, root=1):
 *   1 -> 2, 3
 *   2 -> 4, 5
 *   3 -> 6, 7
 *   5 -> 8
 */

/* adjacency list (children only) */
static int children[MAXN][4];
static int child_cnt[MAXN];

/* query list: each query is (u, v) */
#define MAXQ 8

static int qu[MAXQ], qv[MAXQ]; /* query endpoints */
static int qa[MAXQ];           /* answer per query */
static int nq;                 /* number of queries */

/* query adjacency per node: qlist[u] stores query indices where u appears */
static int qlist[MAXN][MAXQ];
static int qlist_cnt[MAXN];

/* LCA state */
static int ancestor[MAXN]; /* ancestor[u] = "coloured representative of u's set" */
static int visited[MAXN];

static void lca_dfs(int u)
{
    int i;
    dsu_parent[u] = u;
    ancestor[u]   = u;
    visited[u]    = 1;

    /* recurse into children */
    for (i = 0; i < child_cnt[u]; i++) {
        int v = children[u][i];
        lca_dfs(v);
        dsu_union(u, v);
        ancestor[dsu_find(u)] = u;
    }

    /* answer queries incident on u */
    for (i = 0; i < qlist_cnt[u]; i++) {
        int qi = qlist[u][i];
        int other = (qu[qi] == u) ? qv[qi] : qu[qi];
        if (visited[other]) {
            qa[qi] = ancestor[dsu_find(other)];
        }
    }
}

static void add_child(int parent, int child)
{
    children[parent][child_cnt[parent]++] = child;
}

static void add_query(int u, int v, int idx)
{
    qu[idx] = u; qv[idx] = v;
    qlist[u][qlist_cnt[u]++] = idx;
    qlist[v][qlist_cnt[v]++] = idx;
}

void _start(void)
{
    int i;

    /* initialise */
    for (i = 0; i < MAXN; i++) {
        dsu_parent[i] = i;
        ancestor[i] = 0;
        visited[i] = 0;
        child_cnt[i] = 0;
        qlist_cnt[i] = 0;
    }

    /* build tree */
    add_child(1, 2); add_child(1, 3);
    add_child(2, 4); add_child(2, 5);
    add_child(3, 6); add_child(3, 7);
    add_child(5, 8);

    /* define 6 LCA queries */
    nq = 6;
    add_query(4, 8, 0); /* LCA = 2 */
    add_query(4, 5, 1); /* LCA = 2 */
    add_query(6, 7, 2); /* LCA = 3 */
    add_query(4, 6, 3); /* LCA = 1 */
    add_query(8, 3, 4); /* LCA = 1 */
    add_query(5, 8, 5); /* LCA = 5 */

    lca_dfs(1);

    int sum_lca = 0;
    int xor_lca = 0;
    for (i = 0; i < nq; i++) {
        sum_lca += qa[i];
        xor_lca ^= qa[i];
    }

    int n_tests  = nq;           /* 6 */
    int metric_a = sum_lca & 0xFF;
    int metric_b = xor_lca & 0xFF;

    g_result = ((unsigned)n_tests << 16) | ((unsigned)metric_a << 8) | (unsigned)metric_b;
}
