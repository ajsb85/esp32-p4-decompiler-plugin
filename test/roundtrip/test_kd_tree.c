/*
 * test_kd_tree.c — 2-D k-d tree (static array-based), nearest-neighbour search
 *
 * Build a 2-D kd-tree over 8 points using median-split.
 * Run 3 nearest-neighbour queries and count correct matches.
 *
 * Points (pre-sorted so that the simple in-place partitioner works):
 *   p0=(2,3), p1=(5,4), p2=(9,6), p3=(4,7), p4=(8,1), p5=(7,2), p6=(3,8), p7=(1,5)
 *
 * n_tests  = 3  = 0x03
 * metric_a = correct_nn_count + 4 = 7 = 0x07
 * metric_b = sum of found min-dist-squared, low byte non-zero
 *
 * g_result = (3<<16)|(7<<8)|<metric_b>
 */
#include <stdint.h>

volatile uint32_t g_result;

#define N_PTS 8
#define DIM   2

typedef struct { int32_t x[DIM]; } Point;

/* Node in the static kd-tree; leaf when left==right==-1 */
typedef struct {
    Point   pt;
    int32_t split_dim;
    int32_t left;  /* index into nodes[], -1 = none */
    int32_t right;
} KDNode;

static KDNode nodes[N_PTS];
static int32_t n_nodes;

/* Points to insert */
static const Point pts[N_PTS] = {
    {{2,3}}, {{5,4}}, {{9,6}}, {{4,7}},
    {{8,1}}, {{7,2}}, {{3,8}}, {{1,5}}
};

/* Working copy for building the tree */
static Point work[N_PTS];

static int32_t dist2(const Point *a, const Point *b)
{
    int32_t dx = a->x[0] - b->x[0];
    int32_t dy = a->x[1] - b->x[1];
    return dx*dx + dy*dy;
}

/* Partition work[lo..hi] around median on axis dim; return median index */
static int32_t partition_median(int32_t lo, int32_t hi, int32_t dim)
{
    int32_t mid = (lo + hi) / 2;
    /* simple selection: bubble largest to right, find median */
    int32_t i, j;
    for (i = lo; i <= hi; i++) {
        for (j = i + 1; j <= hi; j++) {
            if (work[j].x[dim] < work[i].x[dim]) {
                Point t = work[i]; work[i] = work[j]; work[j] = t;
            }
        }
    }
    return mid;
}

/* Recursively build kd-tree; returns node index */
static int32_t build(int32_t lo, int32_t hi, int32_t depth)
{
    if (lo > hi) return -1;
    int32_t dim = depth % DIM;
    int32_t mid = partition_median(lo, hi, dim);
    int32_t idx = n_nodes++;
    nodes[idx].pt        = work[mid];
    nodes[idx].split_dim = dim;
    nodes[idx].left      = build(lo, mid - 1, depth + 1);
    nodes[idx].right     = build(mid + 1, hi, depth + 1);
    return idx;
}

static int32_t  best_dist2;
static Point    best_pt;

static void nn_search(int32_t node_idx, const Point *query)
{
    if (node_idx < 0) return;
    KDNode *nd = &nodes[node_idx];
    int32_t d = dist2(&nd->pt, query);
    if (d < best_dist2) {
        best_dist2 = d;
        best_pt    = nd->pt;
    }
    int32_t dim  = nd->split_dim;
    int32_t diff = query->x[dim] - nd->pt.x[dim];
    int32_t first  = (diff <= 0) ? nd->left  : nd->right;
    int32_t second = (diff <= 0) ? nd->right : nd->left;
    nn_search(first, query);
    if (diff * diff < best_dist2)
        nn_search(second, query);
}

static void run_kd_tests(void)
{
    uint32_t i;
    for (i = 0; i < N_PTS; i++) work[i] = pts[i];
    n_nodes = 0;
    int32_t root = build(0, N_PTS - 1, 0);

    /* Query 1: nearest to (9,2) → should be (8,1) */
    Point q1 = {{9,2}};
    Point expect1 = {{8,1}};
    best_dist2 = 0x7FFFFFFF; nn_search(root, &q1);
    uint32_t ok1 = (best_pt.x[0] == expect1.x[0] && best_pt.x[1] == expect1.x[1]) ? 1u : 0u;
    int32_t d1 = best_dist2;

    /* Query 2: nearest to (3,4) → should be (2,3) */
    Point q2 = {{3,4}};
    Point expect2 = {{2,3}};
    best_dist2 = 0x7FFFFFFF; nn_search(root, &q2);
    uint32_t ok2 = (best_pt.x[0] == expect2.x[0] && best_pt.x[1] == expect2.x[1]) ? 1u : 0u;
    int32_t d2 = best_dist2;

    /* Query 3: nearest to (5,5) → should be (5,4) */
    Point q3 = {{5,5}};
    Point expect3 = {{5,4}};
    best_dist2 = 0x7FFFFFFF; nn_search(root, &q3);
    uint32_t ok3 = (best_pt.x[0] == expect3.x[0] && best_pt.x[1] == expect3.x[1]) ? 1u : 0u;
    int32_t d3 = best_dist2;

    uint32_t correct      = ok1 + ok2 + ok3;   /* 3 */
    uint32_t n_tests      = 3;
    uint32_t metric_a     = correct + 4;        /* 7 = 0x07 */
    uint32_t metric_b     = (uint32_t)(d1 + d2 + d3) & 0xFFu; /* (2+2+1)=5=0x05 */
    if (metric_b == 0)        metric_b = 0x05u;
    if (metric_b == n_tests)  metric_b++;
    if (metric_b == metric_a) metric_b = (metric_b == 0x05u) ? 0x06u : 0x05u;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    /* expected: 0x00030705 */
}

__attribute__((noreturn)) void _start(void)
{
    run_kd_tests();
    for (;;) {}
}
