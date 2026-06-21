/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Hofstadter G/H/M Sequences fixture.
 *
 * Hofstadter G-sequence: G(0)=0, G(n)=n-G(G(n-1))  (mutual recursion via memoization)
 * Hofstadter H-sequence: H(0)=0, H(n)=n-H(H(H(n-1)))
 * Both are self-referential "nested recursion" sequences.
 *
 * Distinctive decompiler idioms:
 *   1. Self-referential index: `G[n] = n - G[G[n-1]]` (double-indexed table lookup)
 *   2. Triple nested index: `H[n] = n - H[H[H[n-1]]]`
 *   3. Bottom-up DP fill with self-lookup within same array
 *
 * Test: G(0..15) and H(0..15), count fixed-points (G(n)==n or H(n)==n), XOR of G values.
 *
 * G: 0,1,1,2,3,3,4,4,5,6,6,7,8,8,9,9
 * Fixed points of G (G(n)=n): n=0 (G(0)=0), n=1 (G(1)=1) → count=2
 * XOR of G(0..15): 0^1^1^2^3^3^4^4^5^6^6^7^8^8^9^9 = 0^0^3^3^0^0^0^0 = 0... 
 * Let me compute: 0,1,1,2,3,3,4,4,5,6,6,7,8,8,9,9
 * 0^1=1, ^1=0, ^2=2, ^3=1, ^3=2, ^4=6, ^4=2, ^5=7, ^6=1, ^6=7, ^7=0, ^8=8, ^8=0, ^9=9, ^9=0
 * xor_g = 0 — avoid zero, use count instead
 *
 * H: 0,1,1,2,3,3,4,4,4,5,6,6,7,8,8,8 (rough)
 * Actually compute properly in code, count fixed points of H.
 *
 * n_vals=16, g_fixed=2, h_fixed (from code)
 * We'll use: n_terms=16, g_fixed=2, xor_last4 = G(12)^G(13)^G(14)^G(15) = 8^8^9^9=0 — avoid
 * Use sum of G(0..15) mod 256:
 * G sum: 0+1+1+2+3+3+4+4+5+6+6+7+8+8+9+9 = 76 = 0x4C
 *
 * g_result = (16<<16)|(2<<8)|76 = 0x10024C
 */
#include <stdint.h>

volatile uint32_t g_result;

#define HOF_N 16

static uint32_t hof_G[HOF_N];
static uint32_t hof_H[HOF_N];

static void hofstadter_build(void)
{
    uint32_t i;
    hof_G[0] = 0u;
    for (i = 1u; i < HOF_N; i++) {
        /* Hofstadter G: G(n) = n - G(G(n-1)) */
        hof_G[i] = i - hof_G[hof_G[i - 1u]];
    }

    hof_H[0] = 0u;
    for (i = 1u; i < HOF_N; i++) {
        /* Hofstadter H: H(n) = n - H(H(H(n-1))) */
        uint32_t tmp1 = hof_H[i - 1u];
        uint32_t tmp2 = hof_H[tmp1];
        hof_H[i] = i - hof_H[tmp2];
    }
}

void test_hofstadter_sequence(void)
{
    hofstadter_build();

    uint32_t g_fixed = 0u;
    uint32_t g_sum   = 0u;
    uint32_t i;

    for (i = 0u; i < HOF_N; i++) {
        if (hof_G[i] == i) g_fixed++;
        g_sum += hof_G[i];
    }

    /* G sum = 76 = 0x4C, g_fixed = 2 */
    /* g_result = (16<<16)|(2<<8)|76 = 0x10024C */
    g_result = ((uint32_t)HOF_N << 16) | (g_fixed << 8) | (g_sum & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_hofstadter_sequence();
    for (;;);
}
