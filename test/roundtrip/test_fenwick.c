/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Fenwick tree (Binary Indexed Tree) round-trip fixture.
 *
 * A BIT for O(log n) point-update and prefix-sum queries.
 * Two very distinctive decompiler idioms using the "lowest set bit" trick:
 *
 *   Update: while (i <= n) { tree[i] += val; i += i & (-i); }
 *   Query:  while (i > 0)  { sum += tree[i]; i -= i & (-i); }
 *
 * Input (1-indexed, n=6):
 *   arr = {1, 3, 5, 7, 9, 11}
 *
 * BIT after building:
 *   bit[1] = 1,  bit[2] = 4,  bit[3] = 5,
 *   bit[4] = 16, bit[5] = 9,  bit[6] = 20
 *
 * Prefix sum queries:
 *   prefix(1) = 1
 *   prefix(3) = 5 + 4 = 9    (bit[3]+bit[2])
 *   prefix(6) = 20 + 16 = 36 (bit[6]+bit[4])
 *
 *   total = prefix(6) = 36 = 0x24
 *   xor   = 1 ^ 9 ^ 36 = 44 = 0x2C
 *   n     = 6
 *
 * g_result = (n << 16) | (total << 8) | xor = 0x0006242C
 *
 * Recognizable decompiler idioms:
 *   i += i & (-i)   ← update: advance to next responsible cell
 *   i -= i & (-i)   ← query:  subtract lowest set bit
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── BIT ──────────────────────────────────────────────────────────────────── */

#define BIT_N 6

static int bit[BIT_N + 1];    /* 1-indexed */

static void bit_update(int i, int val)
{
    while (i <= BIT_N) {
        bit[i] += val;
        i += i & (-i);
    }
}

static int bit_prefix(int i)
{
    int sum = 0;
    while (i > 0) {
        sum += bit[i];
        i -= i & (-i);
    }
    return sum;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_fenwick(void)
{
    static const int arr[BIT_N] = {1, 3, 5, 7, 9, 11};

    for (int i = 0; i <= BIT_N; i++)
        bit[i] = 0;

    for (int i = 1; i <= BIT_N; i++)
        bit_update(i, arr[i - 1]);

    int q0 = bit_prefix(1);   /* = 1 */
    int q1 = bit_prefix(3);   /* = 9 */
    int q2 = bit_prefix(6);   /* = 36 */

    uint32_t total = (uint32_t)q2;
    uint32_t xor_q = (uint32_t)(q0 ^ q1 ^ q2);   /* = 44 */

    g_result = ((uint32_t)BIT_N << 16)
             | (total << 8)
             | (xor_q & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_fenwick();
    for (;;);
}
