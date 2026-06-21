/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Bitset-Accelerated Subset Sum DP fixture.
 *
 * Uses a single word bitmask as the DP table: bit k is set iff sum k is achievable.
 * Updating for item weight w: dp |= (dp << w)  — a single OR-shift instruction.
 *
 * Distinctive decompiler idioms:
 *   1. `dp |= (dp << a[i])` — core bitset DP update (shift-or)
 *   2. `& mask` where mask = (1 << (W+1)) - 1 — clamp to target width
 *   3. `__builtin_popcount(dp)` or manual bit count — count achievable sums
 *   4. Initial state: `dp = 1` — only sum=0 achievable
 *   5. All updates in O(W/word_size) with WORD-level parallelism
 *
 * Items: [2, 3, 5, 7]  (n=4, W=10)
 * DP evolution:
 *   init:  dp = 0b00000000001 (bit 0 = sum 0)
 *   +w=2:  dp = 0b00000000101 (bits 0,2)
 *   +w=3:  dp = 0b00000101101 (bits 0,2,3,5)
 *   +w=5:  dp = 0b10101101101 (bits 0,2,3,5,7,8,10)
 *   +w=7:  dp = 0b11101101101 (bits 0,2,3,5,7,8,9,10)
 *   mask=(1<<11)-1 = 0x7FF, popcount(dp & mask) = 8
 *
 * Achievable sums ≤ 10: {0,2,3,5,7,8,9,10} = 8 sums
 *
 * n_items    = 4  = 0x04
 * W          = 10 = 0x0A
 * n_achieve  = 8  = 0x08
 *
 * g_result = (n_items << 16) | (W << 8) | n_achieve = 0x040A08
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BS_N 4
#define BS_W 10

static const int bs_a[BS_N] = {2, 3, 5, 7};

void test_bitset_dp(void)
{
    uint32_t dp   = 1u;                      /* bit 0 = sum 0 achievable */
    uint32_t mask = (1u << (BS_W + 1)) - 1; /* keep only bits 0..W */

    for (int i = 0; i < BS_N; i++)
        dp = (dp | (dp << bs_a[i])) & mask;

    /* Count set bits (achievable sums) */
    int cnt = 0;
    for (uint32_t x = dp; x; x >>= 1) cnt += (int)(x & 1u);

    g_result = ((uint32_t)BS_N << 16)
             | ((uint32_t)BS_W << 8)
             | ((uint32_t)cnt & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_bitset_dp();
    for (;;);
}
