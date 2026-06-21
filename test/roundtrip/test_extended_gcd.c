/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Extended GCD fixture.
 *
 * The Extended Euclidean Algorithm computes gcd(a, b) and Bezout coefficients
 * x, y such that a*x + b*y = gcd(a, b).  This also yields modular inverses:
 * x is the modular inverse of a (mod b) when gcd(a,b)==1.
 *
 * Distinctive decompiler idioms:
 *   1. Recursive descent with back-substitution: x = y1, y = x1 - (a/b)*y1
 *   2. Base case: gcd(a,0)=a with x=1, y=0
 *   3. Modular inverse derived as ((x % m) + m) % m
 *   4. Application: solve modular linear equations via inverse
 *
 * Test cases (pairs whose gcd and Bezout coefficients are computed):
 *   (35, 15)  => gcd=5,   inverse of 3 mod 7 = 5
 *   (56, 98)  => gcd=14,  inverse of 3 mod 11 = 4
 *   (17, 31)  => gcd=1,   inverse of 17 mod 31 = 11
 *   (100, 75) => gcd=25,  inverse of 7 mod 13 = 2
 *
 * Metrics:
 *   n_tests   = 4  (number of gcd pairs tested)
 *   gcd_sum   = 5+14+1+25 = 45 => 0x2D  (fits in 8 bits)
 *   inv_xor   = 5^4^11^2 = 8  => 0x08  (XOR of the 4 inverses)
 *
 * g_result = (4<<16)|(0x2D<<8)|0x08 = 0x042D08
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Extended GCD ─────────────────────────────────────────────────────────── */

/*
 * egcd: returns gcd(a, b) and sets *px, *py to Bezout coefficients.
 * Recursive form uses back-substitution on every unwind.
 */
static int egcd(int a, int b, int *px, int *py)
{
    if (b == 0) {
        *px = 1;
        *py = 0;
        return a;
    }
    int x1, y1;
    int g = egcd(b, a % b, &x1, &y1);
    *px = y1;
    *py = x1 - (a / b) * y1;
    return g;
}

/*
 * mod_inv: modular inverse of a modulo m.
 * Returns a^-1 mod m (assumes gcd(a,m)==1).
 * The ((x%m)+m)%m idiom handles negative x from egcd.
 */
static int mod_inv(int a, int m)
{
    int x, y;
    egcd(a, m, &x, &y);
    return ((x % m) + m) % m;
}

/* ── Test pairs ───────────────────────────────────────────────────────────── */

#define N_PAIRS 4

static const int pair_a[N_PAIRS] = {35, 56, 17, 100};
static const int pair_b[N_PAIRS] = {15, 98, 31,  75};

/* inverses: inv_a[i] mod inv_m[i] */
static const int inv_a[N_PAIRS] = {3,  3, 17,  7};
static const int inv_m[N_PAIRS] = {7, 11, 31, 13};

/* expected gcd: {5, 14, 1, 25} */

/* ── Entry point ──────────────────────────────────────────────────────────── */

void test_extended_gcd(void)
{
    uint32_t gcd_sum = 0;
    uint32_t inv_xor = 0;
    int x, y;

    for (int i = 0; i < N_PAIRS; i++) {
        int g = egcd(pair_a[i], pair_b[i], &x, &y);
        gcd_sum += (uint32_t)g;
        int inv = mod_inv(inv_a[i], inv_m[i]);
        inv_xor ^= (uint32_t)inv;
    }
    /* gcd_sum = 5+14+1+25 = 45 = 0x2D
     * inv_xor = 5^4^11^2  =  8 = 0x08
     */
    g_result = ((uint32_t)N_PAIRS << 16) | ((gcd_sum & 0xFFu) << 8) | (inv_xor & 0xFFu);
    /* expected: 0x042D08 */
}

__attribute__((noreturn)) void _start(void)
{
    test_extended_gcd();
    while (1) {}
}
