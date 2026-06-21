/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Inclusion-Exclusion Principle fixture.
 *
 * Counts integers in [1..N] divisible by at least one of {2, 3, 5} using:
 * |A∪B∪C| = |A|+|B|+|C| - |A∩B| - |A∩C| - |B∩C| + |A∩B∩C|
 *
 * Distinctive decompiler idioms:
 *   1. `N/d` — count of multiples of d in [1..N]
 *   2. `a + b + c - ab - ac - bc + abc` — inclusion-exclusion formula
 *   3. Test multiple values of N
 *
 * Test cases:
 *   N=30:  22, N=60:  44, N=100: 74
 *   sum=22+44+74=140=0x8C, xor=22^44^74=112=0x70
 *
 * g_result = (3 << 16) | (140 << 8) | 112 = 0x00038C70
 */
#include <stdint.h>

volatile uint32_t g_result;

static int incl_excl(int n)
{
    int a  = n / 2;
    int b  = n / 3;
    int c  = n / 5;
    int ab = n / 6;
    int ac = n / 10;
    int bc = n / 15;
    int abc= n / 30;
    return a + b + c - ab - ac - bc + abc;
}

void test_inclusion_excl(void)
{
    int r0 = incl_excl(30);  /* 22 */
    int r1 = incl_excl(60);  /* 44 */
    int r2 = incl_excl(100); /* 74 */

    g_result = (3u << 16)
             | ((uint32_t)((r0 + r1 + r2) & 0xFF) << 8)
             | ((uint32_t)((r0 ^ r1 ^ r2) & 0xFF));
}

__attribute__((noreturn)) void _start(void)
{
    test_inclusion_excl();
    for (;;);
}
