/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Segment Tree with Lazy Propagation fixture.
 *
 * Range-add / range-sum segment tree using lazy (deferred) propagation.
 * A pending delta (lazy tag) is stored per node and pushed down before
 * any operation that requires visiting children.
 *
 * Distinctive decompiler idioms:
 *   1. `push_down` before recursion: `if (lazy[node]) { propagate; lazy=0; }`
 *   2. `lazy[2*node] += lazy[node]` — accumulate delta to left child
 *   3. `tree[node] += val * (r - l + 1)` — bulk-update by segment length
 *   4. Recursive split: `if (ql<=l && r<=qr) return tree[node];`
 *
 * Test sequence on array [1,2,3,4,5,6,7,8] (n=8, indices 0..7):
 *   query(0,7)    → initial sum         = 36
 *   update(2,5,+10) → positions 2..5 get +10
 *   query(2,5)    → partial sum         = 13+14+15+16 = 58  (metric_b = 0x3A)
 *   update(0,7,+1)  → all positions +1
 *   query(0,7)    → final sum           = 84                 (metric_a = 0x54)
 *
 * n_tests  = 1 (one complete scenario)
 * metric_a = 84
 * metric_b = 58
 *
 * g_result = (1 << 16) | (84 << 8) | 58 = 0x0001543A
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LST_N     8
#define LST_SIZE  (4 * LST_N)

static int lst_tree[LST_SIZE];
static int lst_lazy[LST_SIZE];

/* ── Build ────────────────────────────────────────────────────────────────── */

static void lst_build(int node, int l, int r, const int *arr)
{
    lst_lazy[node] = 0;
    if (l == r) { lst_tree[node] = arr[l]; return; }
    int mid = (l + r) / 2;
    lst_build(2*node,   l,   mid, arr);
    lst_build(2*node+1, mid+1, r, arr);
    lst_tree[node] = lst_tree[2*node] + lst_tree[2*node+1];
}

/* ── Lazy push-down ───────────────────────────────────────────────────────── */

static void lst_push_down(int node, int l, int r)
{
    if (!lst_lazy[node]) return;
    int mid = (l + r) / 2;
    int lc = 2*node, rc = 2*node+1;
    lst_tree[lc] += lst_lazy[node] * (mid - l + 1);
    lst_lazy[lc] += lst_lazy[node];
    lst_tree[rc] += lst_lazy[node] * (r - mid);
    lst_lazy[rc] += lst_lazy[node];
    lst_lazy[node] = 0;
}

/* ── Range-add update ─────────────────────────────────────────────────────── */

static void lst_update(int node, int l, int r, int ql, int qr, int val)
{
    if (qr < l || r < ql) return;
    if (ql <= l && r <= qr) {
        lst_tree[node] += val * (r - l + 1);
        lst_lazy[node] += val;
        return;
    }
    lst_push_down(node, l, r);
    int mid = (l + r) / 2;
    lst_update(2*node,   l,   mid, ql, qr, val);
    lst_update(2*node+1, mid+1, r, ql, qr, val);
    lst_tree[node] = lst_tree[2*node] + lst_tree[2*node+1];
}

/* ── Range-sum query ──────────────────────────────────────────────────────── */

static int lst_query(int node, int l, int r, int ql, int qr)
{
    if (qr < l || r < ql) return 0;
    if (ql <= l && r <= qr) return lst_tree[node];
    lst_push_down(node, l, r);
    int mid = (l + r) / 2;
    return lst_query(2*node,   l,   mid, ql, qr)
         + lst_query(2*node+1, mid+1, r, ql, qr);
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_lazy_segtree(void)
{
    static const int arr[LST_N] = {1, 2, 3, 4, 5, 6, 7, 8};
    lst_build(1, 0, LST_N - 1, arr);

    /* query(0,7) = 36 — sanity */
    (void)lst_query(1, 0, LST_N-1, 0, LST_N-1);

    /* add 10 to positions 2..5 */
    lst_update(1, 0, LST_N-1, 2, 5, 10);

    /* query(2,5) = 13+14+15+16 = 58 */
    int partial = lst_query(1, 0, LST_N-1, 2, 5);

    /* add 1 to all positions */
    lst_update(1, 0, LST_N-1, 0, LST_N-1, 1);

    /* query(0,7) = 84 */
    int total = lst_query(1, 0, LST_N-1, 0, LST_N-1);

    g_result = (1u << 16)
             | ((uint32_t)total   << 8)
             | ((uint32_t)partial & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_lazy_segtree();
    for (;;);
}
