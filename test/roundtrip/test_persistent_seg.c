/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Persistent Segment Tree fixture.
 *
 * Each point-update creates log2(N) new nodes, sharing unchanged subtrees
 * with the previous version. This makes old versions queryable.
 *
 * Distinctive decompiler idioms:
 *   1. `n = ++ps_pool` — allocate from node pool
 *   2. `ps_left[n]=ps_left[t]; ps_right[n]=ps_right[t]` — node copy (clone)
 *   3. `ps_sum[n] = ps_sum[t] + delta` — incremental sum update
 *   4. Root array: `ps_root[ver+1] = ps_update(ps_root[ver], ...)` — version chain
 *   5. Query on old root: `ps_query(ps_root[old_ver], ...)` — immutable history
 *
 * Array positions 1..4, all starting at 0.
 * Updates:
 *   Version 1: pos 1 += 5  → sum[1..4] = 5
 *   Version 2: pos 3 += 3  → sum[1..4] = 8
 *   Version 3: pos 1 += 2  → sum[1..4] = 10
 *
 * Queries:
 *   q_v3 = sum in version 3 over [1..3] = (5+2) + 0 + 3 = 10
 *   q_v1 = sum in version 1 over [1..1] = 5
 *
 * n_updates  = 3  = 0x03
 * q_v3       = 10 = 0x0A
 * q_v1       = 5  = 0x05
 *
 * g_result = (n_updates << 16) | (q_v3 << 8) | q_v1 = 0x030A05
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PS_N 4          /* array size (positions 1..PS_N) */
#define PS_NODES 256    /* pool capacity (log2(N)*versions*2 is enough) */

static int ps_l[PS_NODES], ps_r[PS_NODES], ps_s[PS_NODES];
static int ps_pool;
static int ps_root[8];  /* roots indexed by version */

static int ps_new(void) { return ++ps_pool; }

/* Persistent point-update: returns new root for updated tree */
static int ps_update(int t, int l, int r, int pos, int delta)
{
    int n = ps_new();
    ps_l[n] = ps_l[t];
    ps_r[n] = ps_r[t];
    ps_s[n] = ps_s[t] + delta;
    if (l == r) return n;
    int mid = (l + r) / 2;
    if (pos <= mid)
        ps_l[n] = ps_update(ps_l[t], l, mid, pos, delta);
    else
        ps_r[n] = ps_update(ps_r[t], mid + 1, r, pos, delta);
    return n;
}

/* Range sum query on any version */
static int ps_query(int t, int l, int r, int ql, int qr)
{
    if (!t || ql > r || qr < l) return 0;
    if (ql <= l && r <= qr) return ps_s[t];
    int mid = (l + r) / 2;
    return ps_query(ps_l[t], l, mid, ql, qr)
         + ps_query(ps_r[t], mid + 1, r, ql, qr);
}

void test_persistent_seg(void)
{
    ps_root[0] = 0;  /* empty initial version */

    ps_root[1] = ps_update(ps_root[0], 1, PS_N, 1, 5);
    ps_root[2] = ps_update(ps_root[1], 1, PS_N, 3, 3);
    ps_root[3] = ps_update(ps_root[2], 1, PS_N, 1, 2);

    int q_v3 = ps_query(ps_root[3], 1, PS_N, 1, 3);  /* 10 */
    int q_v1 = ps_query(ps_root[1], 1, PS_N, 1, 1);  /* 5  */

    g_result = ((uint32_t)3     << 16)
             | ((uint32_t)q_v3 << 8)
             | ((uint32_t)q_v1 & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_persistent_seg();
    for (;;);
}
