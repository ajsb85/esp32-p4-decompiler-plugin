/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Extended Euclidean GCD (Bezout coefficients) fixture.
 *
 * Recursive extended GCD returning Bezout coefficients x, y such that:
 *   gcd(a, b) = x*a + y*b
 *
 * Distinctive decompiler idiom — recursive unwind:
 *   if (b == 0) { *x = 1; *y = 0; return a; }
 *   g = ext_gcd(b, a % b, &x1, &y1);
 *   *x = y1;
 *   *y = x1 - (a / b) * y1;
 *   return g;
 *
 * Three test pairs:
 *   gcd( 35,  15) =  5   ( 1×35  + (-2)×15  =  5)
 *   gcd( 48,  18) =  6   ((-1)×48 +  3×18   =  6)
 *   gcd(100,  75) = 25   ( 1×100 + (-1)×75  = 25)
 *
 * Verification: x*a + y*b == gcd for all three pairs
 *
 *   sum_gcd = 5 + 6 + 25 = 36 = 0x24
 *   xor_gcd = 5 ^ 6 ^ 25 = 26 = 0x1A
 *   n       = 3 (number of pairs)
 *
 * g_result = (n << 16) | (sum_gcd << 8) | (xor_gcd & 0xFF) = 0x0003241A
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Extended GCD ─────────────────────────────────────────────────────────── */

static int ext_gcd(int a, int b, int *x, int *y)
{
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }
    int x1, y1;
    int g = ext_gcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_ext_gcd(void)
{
    static const int pa[] = { 35,  48, 100};
    static const int pb[] = { 15,  18,  75};
    int x, y, g;

    uint32_t sum_g = 0, xor_g = 0;
    for (int k = 0; k < 3; k++) {
        g = ext_gcd(pa[k], pb[k], &x, &y);
        sum_g += (uint32_t)g;
        xor_g ^= (uint32_t)g;
    }

    g_result = (3u << 16)
             | (sum_g << 8)
             | (xor_g & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_ext_gcd();
    for (;;);
}
