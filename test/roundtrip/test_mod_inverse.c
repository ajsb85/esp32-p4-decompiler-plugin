/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Modular Multiplicative Inverse fixture.
 *
 * Computes modinv(a, m) = x such that a*x ≡ 1 (mod m), using the
 * extended Euclidean algorithm to extract the Bezout coefficient.
 *
 * Algorithm:
 *   ext_gcd(a, m) → (g, x, y) with g=gcd, a*x + m*y = g
 *   If g == 1: inverse = ((x % m) + m) % m
 *   Else: no inverse exists (a and m are not coprime)
 *
 * Distinctive decompiler idioms:
 *   1. Mutual recursion unwind: *x = y1; *y = x1 - (a/b)*y1
 *   2. Final normalisation: ((x%m)+m)%m  to handle negative x
 *   3. Guard g==1 check before returning inverse
 *
 * Three test cases (all coprime pairs):
 *   modinv( 3,  7) =  5   (3×5  = 15 ≡ 1 mod  7)
 *   modinv(10, 17) = 12   (10×12 = 120 ≡ 1 mod 17)
 *   modinv( 7, 11) =  8   (7×8  = 56 ≡ 1 mod 11)
 *
 * n        = 3
 * sum_inv  = 5 + 12 + 8 = 25 = 0x19
 * prod_inv = 5 × 12 × 8 = 480; 480 mod 256 = 224 = 0xE0
 *
 * g_result = (n << 16) | (sum_inv << 8) | prod_inv = 0x0003_19E0
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Extended GCD ─────────────────────────────────────────────────────────── */

static int mi_ext_gcd(int a, int b, int *x, int *y)
{
    if (b == 0) { *x = 1; *y = 0; return a; }
    int x1, y1;
    int g = mi_ext_gcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

static int mod_inv(int a, int m)
{
    int x, y;
    int g = mi_ext_gcd(a, m, &x, &y);
    if (g != 1) return -1;
    return ((x % m) + m) % m;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_mod_inverse(void)
{
    static const int pa[] = { 3, 10,  7};
    static const int pm[] = { 7, 17, 11};

    uint32_t sum_inv  = 0;
    uint32_t prod_inv = 1;
    for (int k = 0; k < 3; k++) {
        int inv = mod_inv(pa[k], pm[k]);
        sum_inv  += (uint32_t)inv;
        prod_inv *= (uint32_t)inv;
    }
    /* sum=25=0x19, prod=480→0xE0 */

    g_result = (3u << 16)
             | ((sum_inv & 0xFFu) << 8)
             | (prod_inv & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_mod_inverse();
    for (;;);
}
