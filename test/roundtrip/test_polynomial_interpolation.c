/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Lagrange Polynomial Interpolation (mod p) fixture.
 *
 * Given n (x_i, y_i) pairs, evaluates the unique degree-(n-1) polynomial at a
 * query point using Lagrange's formula:
 *
 *   P(q) = sum_{i=0}^{n-1}  y_i * prod_{j!=i} (q - x_j) / (x_i - x_j)  (mod p)
 *
 * Division mod p uses Fermat's little theorem: a^{-1} = a^{p-2} mod p.
 *
 * Distinctive decompiler idioms:
 *   1. Numerator loop: `num = num * (q - xs[j] + p) % p`  (avoid negative)
 *   2. Denominator loop: `den = den * (xs[i] - xs[j] + p) % p`
 *   3. Modular inverse: `mod_pow(den, p - 2, p)` — Fermat's little theorem
 *   4. Accumulate: `result = (result + y * num % p * inv_den) % p`
 *
 * Test: polynomial f(x) = x^2 + x + 1 (mod 97)
 *   Points: (1,3), (2,7), (3,13)   [f(1)=3, f(2)=7, f(3)=13]
 *   Query at x=5: f(5) = 25+5+1 = 31
 *   Query at x=7: f(7) = 49+7+1 = 57
 *
 * n_queries    = 3   (0x03)
 * result_q5   = 31  (0x1F)
 * result_q7   = 57  (0x39)
 *
 * g_result = (n_queries<<16)|(result_q5<<8)|result_q7 = 0x031F39
 */
#include <stdint.h>

volatile uint32_t g_result;

#define INTERP_MOD 97u

static uint32_t interp_pow(uint32_t base, uint32_t exp, uint32_t mod)
{
    uint32_t r = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1u) r = r * base % mod;
        base = base * base % mod;
        exp >>= 1;
    }
    return r;
}

/* Evaluate Lagrange interpolation at query q given n points (xs, ys) mod p. */
static uint32_t lagrange_eval(const uint32_t *xs, const uint32_t *ys,
                               uint32_t n, uint32_t q, uint32_t p)
{
    uint32_t result = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t num = 1, den = 1;
        for (uint32_t j = 0; j < n; j++) {
            if (j == i) continue;
            num = num * ((q + p - xs[j]) % p) % p;
            den = den * ((xs[i] + p - xs[j]) % p) % p;
        }
        uint32_t inv_den = interp_pow(den, p - 2, p);
        result = (result + ys[i] * num % p * inv_den) % p;
    }
    return result;
}

void test_polynomial_interpolation(void)
{
    /* f(x) = x^2 + x + 1 sampled at x=1,2,3 */
    static const uint32_t xs[3] = {1, 2, 3};
    static const uint32_t ys[3] = {3, 7, 13};

    uint32_t r5 = lagrange_eval(xs, ys, 3, 5, INTERP_MOD);  /* expect 31 */
    uint32_t r7 = lagrange_eval(xs, ys, 3, 7, INTERP_MOD);  /* expect 57 */
    uint32_t n_queries = 3;
    /* pack: (3<<16)|(31<<8)|57 = 0x031F39 */
    g_result = (n_queries << 16) | ((r5 & 0xFFu) << 8) | (r7 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_polynomial_interpolation();
    for (;;);
}
