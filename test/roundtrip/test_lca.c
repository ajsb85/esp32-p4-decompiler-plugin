/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Lowest Common Ancestor (depth leveling) fixture.
 *
 * LCA via depth leveling + upward walk: level the deeper node to the same
 * depth as the shallower, then walk both up together until they meet.
 *
 * Distinctive decompiler idioms:
 *   1. `while (depth[a] > depth[b]) a = par[a]` — level the deeper node
 *   2. `while (a != b) { a = par[a]; b = par[b]; }` — walk up together
 *   3. Static arrays for parent[] and depth[] precomputed from tree structure
 *
 * Tree (1-indexed, root=1):
 *        1
 *       / \
 *      2   3
 *     / \ / \
 *    4  5 6  7
 *
 * Queries: LCA(4,5)=2, LCA(4,6)=1, LCA(2,7)=1
 *
 * n_queries  = 3
 * lca_sum    = 4
 * lca_xor    = 2^1^1 = 2
 *
 * g_result = (n << 16) | (lca_sum << 8) | lca_xor = 0x00030402
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LCA_N 8

static const int lca_par[LCA_N]   = {0, 0, 1, 1, 2, 2, 3, 3};
static const int lca_depth[LCA_N] = {0, 0, 1, 1, 2, 2, 2, 2};

static int lca_query(int a, int b)
{
    while (lca_depth[a] > lca_depth[b]) a = lca_par[a];
    while (lca_depth[b] > lca_depth[a]) b = lca_par[b];
    while (a != b) { a = lca_par[a]; b = lca_par[b]; }
    return a;
}

static const int lca_qa[3] = {4, 4, 2};
static const int lca_qb[3] = {5, 6, 7};

void test_lca(void)
{
    uint32_t lca_sum = 0, lca_xor = 0;
    for (int i = 0; i < 3; i++) {
        uint32_t l = (uint32_t)lca_query(lca_qa[i], lca_qb[i]);
        lca_sum += l;
        lca_xor ^= l;
    }

    g_result = (3u << 16) | ((lca_sum & 0xFFu) << 8) | (lca_xor & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_lca();
    for (;;);
}
