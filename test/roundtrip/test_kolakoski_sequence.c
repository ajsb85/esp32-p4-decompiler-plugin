/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Kolakoski sequence fixture.
 *
 * The Kolakoski sequence over {1, 2} is the unique sequence that is its own
 * run-length encoding:
 *   a(1)=1, a(2)=2, a(3)=2, a(4)=1, a(5)=1, a(6)=2, a(7)=1, a(8)=2, a(9)=2, ...
 *
 * Construction: the sequence tells you the lengths of its own runs.
 *   - Run 1: length a(1)=1  → one 1  → [1]
 *   - Run 2: length a(2)=2  → two 2s → [2, 2]
 *   - Run 3: length a(3)=2  → two 1s → [1, 1]
 *   - Run 4: length a(4)=1  → one 2  → [2]
 *   - ...
 * Concatenating: 1, 2, 2, 1, 1, 2, 1, 2, 2, 1, 2, 2, 1, ...
 *
 * Implementation: iterative pointer-based construction.
 *   - Start with seq[0]=1, seq[1]=2, seq[2]=2
 *   - Read pointer i starts at 2; current symbol alternates 1/2
 *   - Append seq[i] copies of current symbol, toggle symbol, advance i
 *
 * Distinctive decompiler idioms:
 *   1. Self-referential fill loop: `for j in 0..seq[i]-1: seq[len++] = sym`
 *   2. Symbol toggle:  `sym = 3 - sym`
 *   3. Read-pointer advance: `i++` after each run
 *
 * Test: Compute a(1..40), count positions where a(n)==1, XOR those 1-based indices.
 *
 * In a(1..40): count_ones=20=0x14, xor_ones=18=0x12
 *
 * g_result = (40<<16)|(20<<8)|18 = 0x00281412
 * Bytes: 0x28=40, 0x14=20, 0x12=18 — all distinct and non-zero.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define KOL_N 40u

/* Build the first KOL_N terms of the Kolakoski(1,2) sequence in buf[].
 * buf must have space for at least KOL_N elements. */
static void build_kolakoski(uint32_t *buf, uint32_t n)
{
    /* Seed: the sequence starts 1, 2, 2 */
    buf[0] = 1u;
    buf[1] = 2u;
    buf[2] = 2u;

    uint32_t len = 3u;   /* number of terms written so far */
    uint32_t i   = 2u;   /* read pointer into buf (0-indexed) */
    uint32_t sym = 1u;   /* next symbol to emit (after the initial 1,2,2) */

    while (len < n) {
        uint32_t run = buf[i];   /* run length from self-reference */
        uint32_t j;
        for (j = 0u; j < run && len < n; j++) {
            buf[len++] = sym;
        }
        sym = 3u - sym;          /* toggle 1 <-> 2 */
        i++;
    }
}

void test_kolakoski_sequence(void)
{
    uint32_t seq[KOL_N];
    build_kolakoski(seq, KOL_N);

    uint32_t count_ones = 0u;
    uint32_t xor_ones   = 0u;
    uint32_t i;

    for (i = 0u; i < KOL_N; i++) {
        if (seq[i] == 1u) {
            count_ones++;
            xor_ones ^= (i + 1u);   /* 1-based index */
        }
    }

    /* count_ones=20=0x14, xor_ones=18=0x12
     * g_result = (40<<16)|(20<<8)|18 = 0x00281412
     * Bytes: 0x28, 0x14, 0x12 — distinct and non-zero */
    g_result = (KOL_N << 16) | (count_ones << 8) | (xor_ones & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_kolakoski_sequence();
    for (;;);
}
