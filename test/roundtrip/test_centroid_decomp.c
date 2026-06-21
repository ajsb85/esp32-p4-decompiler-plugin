/*
 * test_centroid_decomp.c — centroid decomposition on a small tree (n=7 nodes)
 *
 * Tree edges (0-indexed): 0-1, 0-2, 1-3, 1-4, 2-5, 2-6
 *   (binary tree, root=0, depth 2)
 *
 * Centroid decomposition:
 *   Find centroid of full tree → node 0 (subtree sizes all ≤ 3)
 *   Remove 0 → two subtrees {1,3,4} centroid=1, {2,5,6} centroid=2
 *
 * Tests:
 *   t1: centroid of the full tree is node 0       → ok if centroid==0
 *   t2: centroid of subtree {1,3,4} is node 1     → ok if centroid==1
 *   t3: centroid of subtree {2,5,6} is node 2     → ok if centroid==2
 *
 * g_result = (n_tests<<16)|(metric_a<<8)|metric_b
 *   n_tests  = 3 = 0x03
 *   metric_a = t1_ok+t2_ok+t3_ok + 5 = 8 = 0x08
 *   metric_b = sum of centroid indices + 2 = (0+1+2)+2 = 5 = 0x05
 * → g_result = 0x00030805
 */
#include <stdint.h>

volatile uint32_t g_result;

#define N_NODES 7
#define MAX_DEG 3

/* Adjacency list stored as flat arrays */
static int32_t adj[N_NODES][MAX_DEG];
static int32_t deg[N_NODES];
static uint8_t removed[N_NODES]; /* nodes removed from current decomp step */

static void add_edge(int32_t u, int32_t v)
{
    adj[u][deg[u]++] = v;
    adj[v][deg[v]++] = u;
}

/* Compute subtree size rooted at 'u', coming from 'parent', skipping removed nodes */
static int32_t subtree_size(int32_t u, int32_t parent)
{
    int32_t sz = 1;
    int32_t i;
    for (i = 0; i < deg[u]; i++) {
        int32_t v = adj[u][i];
        if (v == parent || removed[v]) continue;
        sz += subtree_size(v, u);
    }
    return sz;
}

/* Find centroid of the component containing 'u' (size = tree_sz).
 * A centroid has all subtrees ≤ tree_sz/2. */
static int32_t find_centroid(int32_t u, int32_t parent, int32_t tree_sz)
{
    int32_t i;
    for (i = 0; i < deg[u]; i++) {
        int32_t v = adj[u][i];
        if (v == parent || removed[v]) continue;
        int32_t s = subtree_size(v, u);
        if (s > tree_sz / 2)
            return find_centroid(v, u, tree_sz);
    }
    return u;
}

static void run_centroid_tests(void)
{
    int32_t i;
    for (i = 0; i < N_NODES; i++) { deg[i] = 0; removed[i] = 0; }

    /* Build tree */
    add_edge(0,1); add_edge(0,2);
    add_edge(1,3); add_edge(1,4);
    add_edge(2,5); add_edge(2,6);

    /* t1: centroid of full tree (sz=7, starting from node 0) */
    int32_t sz1 = subtree_size(0, -1);  /* = 7 */
    int32_t c1  = find_centroid(0, -1, sz1); /* expect 0 */
    uint32_t t1_ok = (c1 == 0) ? 1u : 0u;

    /* Mark c1 removed, then find centroids of two subtrees */
    removed[c1] = 1;

    /* Subtree rooted at 1 (nodes 1,3,4) */
    int32_t sz2 = subtree_size(1, -1);  /* = 3 */
    int32_t c2  = find_centroid(1, -1, sz2); /* expect 1 */
    uint32_t t2_ok = (c2 == 1) ? 1u : 0u;

    /* Subtree rooted at 2 (nodes 2,5,6) */
    int32_t sz3 = subtree_size(2, -1);  /* = 3 */
    int32_t c3  = find_centroid(2, -1, sz3); /* expect 2 */
    uint32_t t3_ok = (c3 == 2) ? 1u : 0u;

    uint32_t n_tests  = 3;
    uint32_t metric_a = t1_ok + t2_ok + t3_ok + 5; /* 8 = 0x08 */
    uint32_t metric_b = (uint32_t)(c1 + c2 + c3 + 2); /* 5 = 0x05 */
    if (metric_b == 0)        metric_b = 5u;
    if (metric_b == n_tests)  metric_b++;
    if (metric_b == metric_a) metric_b = (metric_b <= 4u) ? metric_b + 1u : metric_b - 1u;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    /* expected: 0x00030805 */
}

__attribute__((noreturn)) void _start(void)
{
    run_centroid_tests();
    for (;;) {}
}
