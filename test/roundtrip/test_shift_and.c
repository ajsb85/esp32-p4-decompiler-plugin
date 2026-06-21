/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Shift-And Pattern Matching fixture.
 *
 * The Shift-And algorithm uses a bitset D where bit j is set iff the first
 * j+1 characters of the pattern P match ending at the current text position.
 *
 * Distinctive decompiler idioms:
 *   1. `mask[P[j]] |= (1u << j)` — build character bitmask (bit j = char j of pattern)
 *   2. `D = ((D << 1) | 1u) & mask[T[i]]` — shift state left, OR in bit 0, mask by char
 *   3. `if (D & (1u << (m-1))) matches++` — top bit set = full pattern match
 *   4. Single word D = state vector; no explicit state array
 *   5. `mask[128]` — character → bitmask mapping table
 *
 * Pattern: "aba" (m=3), Text: "ababab" (n=6)
 * mask['a'] = 0b101 (positions 0,2 in P are 'a')
 * mask['b'] = 0b010 (position 1 in P is 'b')
 *
 * Trace:
 *   T[0]='a': D = (0b000_1)|1 & 101 = 001
 *   T[1]='b': D = (001_1)|1 & 010 = 011 & 010 = 010
 *   T[2]='a': D = (010_1)|1 & 101 = 101 → bit 2 set → MATCH (P ends at pos 2)
 *   T[3]='b': D = (101_1)|1 & 010 = (111 truncated to 3 bits = 011) & 010 = 010
 *              Wait: (101 << 1 = 1010; 1010|1 = 1011; &0b111 = 011) & 010 = 010
 *   T[4]='a': D = (011_1)|1 & 101 = (0111 & 111 = 111) & 101 = 101 → MATCH (pos 4)
 *   T[5]='b': D = (101_1)|1 & 010 = (1011 & 111 = 011) & 010 = 010
 * n_matches = 2 (at text positions 2 and 4)
 *
 * n_matches = 2  = 0x02
 * text_len  = 6  = 0x06
 * pat_len   = 3  = 0x03
 *
 * g_result = (n_matches << 16) | (text_len << 8) | pat_len = 0x020603
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SA_M 3
#define SA_N 6

static const unsigned char sa_p[SA_M] = {'a', 'b', 'a'};
static const unsigned char sa_t[SA_N] = {'a', 'b', 'a', 'b', 'a', 'b'};

static unsigned sa_mask[256];

void test_shift_and(void)
{
    for (int j = 0; j < SA_M; j++)
        sa_mask[sa_p[j]] |= (1u << j);

    unsigned D = 0;
    int matches = 0;
    for (int i = 0; i < SA_N; i++) {
        D = ((D << 1) | 1u) & sa_mask[sa_t[i]];
        if (D & (1u << (SA_M - 1))) matches++;
    }
    /* matches=2 */

    g_result = ((uint32_t)matches << 16)
             | ((uint32_t)SA_N   << 8)
             | ((uint32_t)SA_M & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_shift_and();
    for (;;);
}
