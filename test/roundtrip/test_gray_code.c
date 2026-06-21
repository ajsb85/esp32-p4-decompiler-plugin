/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Gray Code generation fixture.
 *
 * Gray code: G(i) = i ^ (i >> 1). Consecutive codes differ by exactly 1 bit.
 *
 * Distinctive decompiler idioms:
 *   1. `G[i] = i ^ (i >> 1)` — XOR with arithmetic right-shift
 *   2. `popcount(G[i] ^ G[i+1]) == 1` — single-bit transition check
 *   3. `G[n_codes-1] ^ G[0] == ... ` — wrap-around differs by 1 bit
 *
 * n_bits=3, n_codes=8:
 *   G = {0,1,3,2,6,7,5,4}
 *   last = G[7] = 7^(7>>1) = 7^3 = 4
 *
 * g_result = (n_codes << 16) | (n_bits << 8) | last = 0x00080304
 */
#include <stdint.h>

volatile uint32_t g_result;

#define GC_N    8
#define GC_BITS 3

static int gc_code[GC_N];

void test_gray_code(void)
{
    for (int i = 0; i < GC_N; i++)
        gc_code[i] = i ^ (i >> 1);

    /* verify: each consecutive pair differs by exactly 1 bit */
    int valid = 1;
    for (int i = 0; i < GC_N - 1; i++) {
        int diff = gc_code[i] ^ gc_code[i + 1];
        if (diff == 0 || (diff & (diff - 1)) != 0)
            valid = 0;
    }
    (void)valid;

    int last = gc_code[GC_N - 1]; /* = 4 */

    g_result = ((uint32_t)GC_N << 16)
             | ((uint32_t)GC_BITS << 8)
             | ((uint32_t)last & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_gray_code();
    for (;;);
}
