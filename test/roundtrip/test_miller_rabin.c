/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Miller-Rabin Primality Test fixture.
 *
 * Probabilistic (deterministic for small n) primality test using modular
 * exponentiation and Fermat-witness squaring.
 *
 * Algorithm for each witness a:
 *   1. Write n-1 = 2^s * d  (extract powers of 2)
 *   2. x = mod_pow(a, d, n)
 *   3. If x==1 or x==n-1: no refutation from this witness
 *   4. Square s-1 times: if x→n-1 at any step: no refutation
 *   5. If x never reaches 1 or n-1: n is COMPOSITE
 *
 * Distinctive decompiler idioms:
 *   1. Extract powers of 2: `while (d%2==0) { d>>=1; s++; }` (before main loop)
 *   2. Modular squaring loop: `for (r=1; r<s; r++) { x=x*x%n; if(x==n-1) break; }`
 *   3. Witness loop: `if (r==s) return 0` — composite verdict
 *   4. Deterministic witnesses for n<3.2B: {2,3,5,7}
 *
 * Test values: {2, 3, 5, 9, 11, 15, 17, 97}
 * Primes:      {2, 3, 5, 11, 17, 97}  count=6
 * Composites:  {9, 15}                count=2
 *
 * n_vals     = 8
 * count_p    = 6
 * xor_primes = 2^3^5^11^17^97 = 127  (0x7F)
 *
 * g_result = (n_vals << 16) | (count_p << 8) | xor_primes = 0x0008067F
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Miller-Rabin ─────────────────────────────────────────────────────────── */

#define MR_N 8

static const int mr_vals[MR_N] = {2, 3, 5, 9, 11, 15, 17, 97};

static int mr_pow(int a, int e, int m)
{
    int r = 1;
    a %= m;
    while (e > 0) {
        if (e & 1) r = r * a % m;
        a = a * a % m;
        e >>= 1;
    }
    return r;
}

static int miller_rabin(int n)
{
    if (n < 2)  return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;

    /* write n-1 = 2^s * d */
    int d = n - 1, s = 0;
    while (d % 2 == 0) { d >>= 1; s++; }

    static const int witnesses[] = {2, 3, 5, 7};
    for (int wi = 0; wi < 4; wi++) {
        int a = witnesses[wi];
        if (a >= n) continue;
        int x = mr_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;
        int r;
        for (r = 1; r < s; r++) {
            x = x * x % n;
            if (x == n - 1) break;
        }
        if (r == s) return 0; /* composite — witness a refutes primality */
    }
    return 1; /* probable prime (deterministic for n < 3,215,031,751) */
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_miller_rabin(void)
{
    uint32_t count_p = 0, xor_p = 0;
    for (int i = 0; i < MR_N; i++) {
        if (miller_rabin(mr_vals[i])) {
            count_p++;
            xor_p ^= (uint32_t)mr_vals[i];
        }
    }
    /* primes: {2,3,5,11,17,97}; count=6, xor=127 */

    g_result = ((uint32_t)MR_N << 16) | (count_p << 8) | (xor_p & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_miller_rabin();
    for (;;);
}
