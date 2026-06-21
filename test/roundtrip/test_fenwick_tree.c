/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Fenwick Tree (Binary Indexed Tree) fixture.
 *
 * Fenwick tree supports O(log n) prefix-sum queries and O(log n) point
 * updates via the bit-manipulation trick `i += i & (-i)`.
 *
 * Distinctive decompiler idioms:
 *   1. `for(i++;i<=n;i+=i&(-i)) bit[i]+=delta` — BIT update loop
 *   2. `for(i++;i>0;i-=i&(-i)) s+=bit[i]` — BIT query loop
 *   3. range(l,r) = query(r) - query(l-1) — range sum from prefix sums
 *   4. `bit[i] += delta` inside the update loop
 *
 * Array {2,1,1,3,2,3,4,5} (n=8, 0-indexed):
 *   prefix_sum[0..4] = 2+1+1+3+2 = 9
 *   point update: arr[3] += 3  (arr[3] becomes 6)
 *   range_sum[2..5] after update = 1+6+2+3 = 12
 *
 * n=8, p1=9, p2=12
 *
 * g_result = (8<<16) | (9<<8) | 12 = 0x0008090C
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FW_N 8

static int fw_bit[FW_N + 1];

static void fw_update(int i, int delta)
{
    for (i++; i <= FW_N; i += i & (-i))
        fw_bit[i] += delta;
}

static int fw_query(int i)
{
    int s = 0;
    for (i++; i > 0; i -= i & (-i))
        s += fw_bit[i];
    return s;
}

static int fw_range(int l, int r)
{
    return fw_query(r) - (l > 0 ? fw_query(l - 1) : 0);
}

void test_fenwick_tree(void)
{
    static const int arr[FW_N] = {2,1,1,3,2,3,4,5};
    for (int i = 0; i <= FW_N; i++) fw_bit[i] = 0;
    for (int i = 0; i < FW_N; i++) fw_update(i, arr[i]);

    int p1 = fw_range(0, 4);  /* 2+1+1+3+2 = 9 */
    fw_update(3, 3);           /* arr[3] += 3 → 6 */
    int p2 = fw_range(2, 5);  /* 1+6+2+3 = 12 */

    g_result = ((uint32_t)FW_N << 16)
             | ((uint32_t)(p1 & 0xFF) << 8)
             | (uint32_t)(p2 & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_fenwick_tree();
    for (;;);
}
