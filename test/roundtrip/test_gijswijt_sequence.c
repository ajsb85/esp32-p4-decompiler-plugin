/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Gijswijt's sequence fixture.
 *
 * Gijswijt's sequence (OEIS A090822): a(n) = largest k such that the tail
 * of a(1..n-1) can be written as (some block) repeated k times.
 *
 * First terms: 1, 1, 2, 1, 1, 2, 2, 2, 3, 1, 1, 2, 1, 1, 2, 2, 2, 3, 2, ...
 *
 * The sequence grows very slowly — the value 4 first appears around position
 * 10^(10^23), so the first 30 terms only contain 1s, 2s, and one 3.
 *
 * Algorithm to compute a(n) given a(1..n-1):
 *   For each block length L from n-1 down to 1:
 *     Let B = a[n-L .. n-1]  (the last L elements)
 *     Count how many consecutive times B appears just before position n-1
 *     If that count >= 2, record it and break
 *   If no repetition found, a(n) = 1.
 *
 * Distinctive decompiler idioms:
 *   1. Inner loop counting backward by block size: `start = tail - (rep+1)*L`
 *   2. Block comparison loop: `for j in 0..L-1: if a[start+j] != a[tail-L+j]`
 *   3. Outer scan from largest L down to 1 returning on first rep >= 2
 *
 * Test: Compute a(1..30), count positions where a(n)==1, XOR those 1-based indices.
 *
 * In a(1..30): count_ones=14=0x0e, xor_ones_idx=13=0x0d
 *
 * g_result = (30<<16)|(14<<8)|13 = 0x001e0e0d
 * Bytes: 0x1e=30, 0x0e=14, 0x0d=13 — all distinct and non-zero.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define GIJ_N 30u

/* Count how many consecutive full copies of the last L elements appear at the
 * tail of seq[0..m-1].  Returns the repetition count (>= 1 always). */
static uint32_t tail_rep(const uint32_t *seq, uint32_t m, uint32_t L)
{
    uint32_t rep = 1u;
    for (;;) {
        uint32_t needed = (rep + 1u) * L;
        if (needed > m) break;
        uint32_t base = m - needed;           /* start of candidate copy */
        uint32_t ref  = m - L;               /* the reference block */
        uint32_t j;
        int match = 1;
        for (j = 0u; j < L; j++) {
            if (seq[base + j] != seq[ref + j]) {
                match = 0;
                break;
            }
        }
        if (!match) break;
        rep++;
    }
    return rep;
}

/* Compute the next term of Gijswijt's sequence given seq[0..m-1]. */
static uint32_t gijswijt_next(const uint32_t *seq, uint32_t m)
{
    uint32_t best = 1u;
    uint32_t L;
    for (L = m; L >= 1u; L--) {
        uint32_t r = tail_rep(seq, m, L);
        if (r > best) {
            best = r;
        }
        /* Optimisation: once we have a repeat count r, no shorter block
         * can give a higher k (because shorter blocks embed shorter tails).
         * We keep scanning to be safe — still O(m^2) but correct. */
    }
    return best;
}

void test_gijswijt_sequence(void)
{
    uint32_t seq[GIJ_N];

    /* Seed first four known terms */
    seq[0] = 1u;
    seq[1] = 1u;
    seq[2] = 2u;
    seq[3] = 1u;

    uint32_t i;
    for (i = 4u; i < GIJ_N; i++) {
        seq[i] = gijswijt_next(seq, i);
    }

    uint32_t count_ones = 0u;
    uint32_t xor_ones   = 0u;

    for (i = 0u; i < GIJ_N; i++) {
        if (seq[i] == 1u) {
            count_ones++;
            xor_ones ^= (i + 1u);   /* 1-based index */
        }
    }

    /* count_ones=14=0x0e, xor_ones=13=0x0d
     * g_result = (30<<16)|(14<<8)|13 = 0x001e0e0d
     * Bytes: 0x1e, 0x0e, 0x0d — distinct and non-zero */
    g_result = (GIJ_N << 16) | (count_ones << 8) | (xor_ones & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_gijswijt_sequence();
    for (;;);
}
