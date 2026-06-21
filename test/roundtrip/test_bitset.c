/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Bitset (uint32_t) operations round-trip fixture.
 *
 * A compact bitset backed by a single uint32_t.  Tests set/test membership,
 * Kernighan popcount, union and intersection of two bitsets.
 *
 * Set A members (positions): {1, 3, 5, 7, 9, 11}
 *   bitset_a = (1<<1)|(1<<3)|(1<<5)|(1<<7)|(1<<9)|(1<<11) = 0x00000AAA
 *
 * Set B members (positions): {3, 5, 7, 11, 13, 17}
 *   bitset_b = (1<<3)|(1<<5)|(1<<7)|(1<<11)|(1<<13)|(1<<17) = 0x000228A8
 *
 * Union     (A | B): positions {1,3,5,7,9,11,13,17} → 8 bits set
 * Intersect (A & B): positions {3,5,7,11}            → 4 bits set
 *
 * XOR of union positions: 1^3^5^7^9^11^13^17 = 30 = 0x1E
 *
 * g_result = (popcount_union << 16) | (popcount_intersect << 8) | xor_union_pos
 *           = (8 << 16) | (4 << 8) | 30 = 0x0008041E
 *
 * Recognizable decompiler idioms:
 *   *bs |= (1u << pos)            ← set bit
 *   (*bs >> pos) & 1              ← test bit
 *   while (w) { w &= w-1; cnt++; } ← Kernighan popcount
 *   union_bs = a | b; isect_bs = a & b;  ← word-level ops
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Bitset primitives (single uint32_t) ─────────────────────────────────── */

static void bs_set(uint32_t *bs, int pos) { *bs |= (1u << pos); }
static int  bs_test(const uint32_t *bs, int pos) { return ((*bs) >> pos) & 1; }

static int bs_popcount(uint32_t w)
{
    int cnt = 0;
    while (w) { w &= w - 1; cnt++; }
    return cnt;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_bitset(void)
{
    static const int set_a[6] = {1, 3, 5, 7, 9, 11};
    static const int set_b[6] = {3, 5, 7, 11, 13, 17};

    uint32_t bitset_a = 0, bitset_b = 0;
    for (int i = 0; i < 6; i++) {
        bs_set(&bitset_a, set_a[i]);
        bs_set(&bitset_b, set_b[i]);
    }
    (void)bs_test;   /* silence unused-function warning */

    uint32_t union_bs  = bitset_a | bitset_b;
    uint32_t isect_bs  = bitset_a & bitset_b;

    int pop_union = bs_popcount(union_bs);
    int pop_isect = bs_popcount(isect_bs);

    /* XOR of bit positions that are set in the union */
    uint32_t xor_pos = 0;
    for (int b = 0; b < 32; b++)
        if ((union_bs >> b) & 1)
            xor_pos ^= (uint32_t)b;

    g_result = ((uint32_t)pop_union << 16)
             | ((uint32_t)pop_isect << 8)
             | (xor_pos & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_bitset();
    for (;;);
}
