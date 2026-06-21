/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Dominator Tree (Lengauer-Tarjan) fixture.
 *
 * The dominator tree of a directed graph rooted at r shows: node u dominates
 * node v iff every path from r to v passes through u.  The immediate dominator
 * (idom) of v is the closest strict dominator.
 *
 * This implements a simplified iterative Cooper-Harvey-Kennedy dataflow
 * algorithm (often called the "simple" dominator algorithm):
 *   For each node n in reverse post-order (skipping start):
 *     new_idom = first already-processed predecessor
 *     for all other predecessors p of n:
 *       if idom[p] != UNDEF: new_idom = intersect(new_idom, p)
 *     if idom[n] != new_idom: idom[n] = new_idom; changed = true
 *   Repeat until no change.
 *
 * intersect(b1, b2): walk up both fingers until they meet (in RPO order).
 *
 * Test graph (6 nodes 0-5, rooted at 0):
 *   0 -> 1, 2
 *   1 -> 3
 *   2 -> 3, 4
 *   3 -> 5
 *   4 -> 5
 *   5 -> (none)
 *
 * RPO from 0: 0,1,2,3,4,5  (post-order reversed)
 * idom[0]=0 (root self-dom), idom[1]=0, idom[2]=0,
 * idom[3]=0 (both paths go through 0), idom[4]=2, idom[5]=0
 *   (both 3 and 4 dominated only by 0)
 *
 * Distinct metric values (non-zero, distinct):
 *   n_tests  = 6   (number of nodes)
 *   idom_sum = idom[1]+idom[2]+idom[3]+idom[4]+idom[5]
 *            = 0+0+0+2+0 = 2  => too small; use XOR instead
 *   idom_xor = 0^0^0^2^0 = 2  => still too small
 *
 * Use a different graph to get better metrics.
 * Graph (7 nodes 0-6, rooted at 0):
 *   0 -> 1, 2
 *   1 -> 3, 4
 *   2 -> 4, 5
 *   3 -> 6
 *   4 -> 6
 *   5 -> 6
 *   6 -> (none)
 *
 * idom: 0->0, 1->0, 2->0, 3->1, 4->0 (join of 1 and 2), 5->2, 6->0
 * idom_xor of non-root = 0^0^1^0^2^0 = 3  => still small
 *
 * Let's use node weights: idom[i]*weight[i]
 * weight = {10,20,30,40,50,60} for nodes 1-6
 * sum = 0*10+0*20+1*30+0*40+2*50+0*60 = 30+100 = 130 => too big for uint8
 *
 * Simpler approach: report count of nodes dominated directly by 0 (idom==0)
 * Direct dom-children of 0: {1,2,4,6} = 4 nodes
 * Direct dom-children of 1: {3}
 * Direct dom-children of 2: {5}
 *
 * Metrics for 7-node graph:
 *   n_tests   = 7   (0x07)
 *   idom_sum  = (sum of idom array for nodes 1..6) = 0+0+1+0+2+0 = 3  (0x03)
 *              => not distinct from n_tests easily; use idom_sum differently
 *   dom_xor   = idom[1]^idom[2]^idom[3]^idom[4]^idom[5]^idom[6]
 *             = 0^0^1^0^2^0 = 3  (0x03) -- same as sum, not distinct from it
 *
 * Use a cleaner approach: count dominated nodes per level
 *   depth[0]=0, depth[1]=1, depth[2]=1, depth[3]=2, depth[4]=1, depth[5]=2, depth[6]=1
 *   depth_sum = 0+1+1+2+1+2+1 = 8 = 0x08
 *
 * Final metrics (all non-zero and distinct):
 *   n_tests   = 7          (0x07) — number of nodes
 *   idom_csum = 3          (0x03) — sum of idom values for nodes 1-6
 *   depth_sum = 8          (0x08) — sum of dominator-tree depths for all nodes
 *
 * g_result = (7<<16)|(3<<8)|8 = 0x070308
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Dominator Tree (iterative Cooper-Harvey-Kennedy) ─────────────────────── */

#define DOM_N    7      /* number of nodes */
#define DOM_ROOT 0
#define DOM_UNDEF (-1)

/* Adjacency list (predecessors per node, stored as flat arrays) */
static const int pred_0[] = {-1};           /* node 0: no predecessors */
static const int pred_1[] = {0, -1};
static const int pred_2[] = {0, -1};
static const int pred_3[] = {1, -1};
static const int pred_4[] = {1, 2, -1};
static const int pred_5[] = {2, -1};
static const int pred_6[] = {3, 4, 5, -1};

static const int *preds[DOM_N] = {
    pred_0, pred_1, pred_2, pred_3, pred_4, pred_5, pred_6
};

/* RPO (reverse post-order) for this graph: 0,1,2,3,4,5,6 */
static const int rpo[DOM_N] = {0, 1, 2, 3, 4, 5, 6};
/* rpo_idx[v] = position of v in RPO array (== v here since RPO is identity) */
static const int rpo_idx[DOM_N] = {0, 1, 2, 3, 4, 5, 6};

static int idom[DOM_N];

/* Walk up the dominator tree until b1 and b2 meet (in RPO order) */
static int dom_intersect(int b1, int b2)
{
    while (b1 != b2) {
        while (rpo_idx[b1] > rpo_idx[b2]) b1 = idom[b1];
        while (rpo_idx[b2] > rpo_idx[b1]) b2 = idom[b2];
    }
    return b1;
}

static void dom_compute(void)
{
    /* Initialise */
    for (int i = 0; i < DOM_N; i++) idom[i] = DOM_UNDEF;
    idom[DOM_ROOT] = DOM_ROOT;

    int changed = 1;
    while (changed) {
        changed = 0;
        /* iterate in RPO order, skip root */
        for (int ri = 1; ri < DOM_N; ri++) {
            int n = rpo[ri];
            int new_idom = DOM_UNDEF;

            /* iterate over predecessors */
            for (int pi = 0; preds[n][pi] != -1; pi++) {
                int p = preds[n][pi];
                if (idom[p] == DOM_UNDEF) continue;
                if (new_idom == DOM_UNDEF) {
                    new_idom = p;
                } else {
                    new_idom = dom_intersect(new_idom, p);
                }
            }
            if (new_idom != DOM_UNDEF && idom[n] != new_idom) {
                idom[n] = new_idom;
                changed = 1;
            }
        }
    }
}

/* Compute depth of node v in dominator tree */
static int dom_depth(int v)
{
    int d = 0;
    while (v != DOM_ROOT) {
        v = idom[v];
        d++;
    }
    return d;
}

/* ── Entry point ──────────────────────────────────────────────────────────── */

void test_dominator_tree(void)
{
    dom_compute();

    /* idom: [0,0,0,1,0,2,0]
     * idom_csum = idom[1]+idom[2]+idom[3]+idom[4]+idom[5]+idom[6]
     *           = 0+0+1+0+2+0 = 3
     */
    uint32_t idom_csum = 0;
    for (int i = 1; i < DOM_N; i++) {
        idom_csum += (uint32_t)idom[i];
    }

    /* depth: [0,1,1,2,1,2,1]
     * depth_sum = 0+1+1+2+1+2+1 = 8
     */
    uint32_t depth_sum = 0;
    for (int i = 0; i < DOM_N; i++) {
        depth_sum += (uint32_t)dom_depth(i);
    }

    g_result = ((uint32_t)DOM_N << 16) | ((idom_csum & 0xFFu) << 8) | (depth_sum & 0xFFu);
    /* expected: (7<<16)|(3<<8)|8 = 0x070308 */
}

__attribute__((noreturn)) void _start(void)
{
    test_dominator_tree();
    while (1) {}
}
