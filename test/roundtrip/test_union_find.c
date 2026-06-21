/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Disjoint Set Union (Union-Find) round-trip fixture.
 *
 * Implements a Union-Find with:
 *   - Path compression (two-pass iterative find)
 *   - Union by rank (attach smaller-rank root under larger-rank root)
 *
 * Recognizable decompiler idioms:
 *   while (parent[x] != x) x = parent[x];  ← find traversal
 *   parent[x] = root;                        ← path compression
 *   if (rank[a] < rank[b]) swap(a, b);      ← rank comparison
 *   if (rank[a] == rank[b]) rank[a]++;       ← rank bump on equal merge
 *
 * n = 8 elements (0–7), 7 union operations:
 *   (0,1) (2,3) (4,5) (6,7) (1,2) (5,6) (3,4)
 *
 * After all unions: one connected component.
 *   Root of component = 0 (determined by union-by-rank order).
 *
 *   sum_rank = rank[0]+…+rank[7] = 3+0+1+0+2+0+1+0 = 7
 *   xor_root = find(0)^…^find(7) = 0^0^…^0 = 0
 *
 * g_result = (n << 16) | (sum_rank << 8) | xor_root = 0x00080700
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Union-Find ──────────────────────────────────────────────────────────── */

#define UF_MAX 16

static int uf_parent[UF_MAX];
static int uf_rank[UF_MAX];

static void uf_init(int n)
{
    for (int i = 0; i < n; i++) {
        uf_parent[i] = i;
        uf_rank[i]   = 0;
    }
}

/* Iterative find with path compression (two-pass). */
static int uf_find(int x)
{
    int root = x;
    while (uf_parent[root] != root)
        root = uf_parent[root];
    /* Path compression: redirect all nodes on path to root. */
    while (uf_parent[x] != root) {
        int next = uf_parent[x];
        uf_parent[x] = root;
        x = next;
    }
    return root;
}

/* Union by rank. */
static void uf_union(int a, int b)
{
    a = uf_find(a);
    b = uf_find(b);
    if (a == b) return;
    if (uf_rank[a] < uf_rank[b]) {
        int tmp = a; a = b; b = tmp;
    }
    uf_parent[b] = a;
    if (uf_rank[a] == uf_rank[b])
        uf_rank[a]++;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_union_find(void)
{
    static const int ops[7][2] = {
        {0,1}, {2,3}, {4,5}, {6,7}, {1,2}, {5,6}, {3,4}
    };

    uf_init(8);

    for (int i = 0; i < 7; i++)
        uf_union(ops[i][0], ops[i][1]);

    uint32_t sum_rank = 0, xor_root = 0;
    for (int i = 0; i < 8; i++) {
        sum_rank += (uint32_t)uf_rank[i];
        xor_root ^= (uint32_t)uf_find(i);
    }

    g_result = (8u << 16) | (sum_rank << 8) | (xor_root & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_union_find();
    for (;;);
}
