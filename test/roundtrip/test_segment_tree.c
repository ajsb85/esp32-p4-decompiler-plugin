/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Segment tree (range sum query) round-trip fixture.
 *
 * A power-of-2-size array-backed segment tree supporting O(log n) range sum.
 *
 * Build idiom (bottom-up):
 *   for (i = n-1; i >= 1; i--)
 *     tree[i] = tree[2*i] + tree[2*i+1];
 *
 * Query idiom (half-open range [lo, hi) in tree indices):
 *   while (l < r) {
 *     if (l & 1) sum += tree[l++];
 *     if (r & 1) sum += tree[--r];
 *     l >>= 1; r >>= 1;
 *   }
 *
 * Input array (n=8):
 *   {2, 4, 6, 8, 10, 12, 14, 16}
 *   Total = 72
 *
 * Tree (1-indexed, leaves at [8..15]):
 *   tree[1]=72, tree[2]=20, tree[3]=52
 *   tree[4]=6,  tree[5]=14, tree[6]=22, tree[7]=30
 *   tree[8..15] = {2,4,6,8,10,12,14,16}
 *
 * Three range sum queries (0-indexed, inclusive [lo, hi]):
 *   sum([0, 7]) = 72    ← full range
 *   sum([2, 5]) = 36    ← 6+8+10+12
 *   sum([1, 4]) = 28    ← 4+6+8+10
 *
 *   xor_queries = 72^36^28 = 112 = 0x70
 *
 * g_result = (n << 16) | (total << 8) | xor_queries = 0x00084870
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Segment tree ─────────────────────────────────────────────────────────── */

#define SEG_N   8   /* must be power of 2 */

static uint32_t seg_tree[2 * SEG_N];

static void seg_build(const uint32_t *arr, int n)
{
    /* Load leaves */
    for (int i = 0; i < n; i++)
        seg_tree[n + i] = arr[i];
    /* Build internal nodes bottom-up */
    for (int i = n - 1; i >= 1; i--)
        seg_tree[i] = seg_tree[2 * i] + seg_tree[2 * i + 1];
}

static uint32_t seg_query(int n, int lo, int hi)   /* inclusive [lo, hi] */
{
    uint32_t sum = 0;
    int l = n + lo;
    int r = n + hi + 1;    /* half-open */
    while (l < r) {
        if (l & 1) sum += seg_tree[l++];
        if (r & 1) sum += seg_tree[--r];
        l >>= 1;
        r >>= 1;
    }
    return sum;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_segment_tree(void)
{
    static const uint32_t arr[SEG_N] = {2, 4, 6, 8, 10, 12, 14, 16};
    seg_build(arr, SEG_N);

    uint32_t q0 = seg_query(SEG_N, 0, 7);   /* = 72 */
    uint32_t q1 = seg_query(SEG_N, 2, 5);   /* = 36 */
    uint32_t q2 = seg_query(SEG_N, 1, 4);   /* = 28 */

    uint32_t total = seg_tree[1];            /* root = total sum = 72 */

    g_result = ((uint32_t)SEG_N << 16)
             | (total << 8)
             | ((q0 ^ q1 ^ q2) & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_segment_tree();
    for (;;);
}
