/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Primitive Root (mod p) fixture.
 *
 * A primitive root g of prime p is an integer such that g^1, g^2, ..., g^(p-1)
 * are all distinct modulo p (i.e., ord_p(g) == p-1).
 *
 * Algorithm:
 *   1. Factorise p-1 into prime factors f[0..k-1].
 *   2. For candidate g=2,3,...: check g^((p-1)/f[i]) != 1 (mod p) for all i.
 *   3. First g satisfying all checks is a primitive root.
 *
 * Distinctive decompiler idioms:
 *   1. Factor loop: `while (rem % f == 0) rem /= f`  (trial division of p-1)
 *   2. Primitive root check: `if (mod_pow(g, (p-1)/f, p) == 1) break` (inner)
 *   3. Order verification: g^((p-1)/f[i]) != 1 for all prime factors f[i]
 *   4. Modular exponentiation: `r = r * a % m` inside bit-scan loop
 *
 * Test primes: {7, 11, 13, 17, 19}
 * Primitive roots (smallest): {3, 2, 2, 3, 2}
 * XOR of roots: 3^2^2^3^2 = 2  (0x02)
 * Sum of roots (mod 256): (3+2+2+3+2) = 12  (0x0C)
 *
 * g_result = (n_primes<<16)|(xor_roots<<8)|sum_roots = 0x05020C
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PR_N 5

static const uint32_t pr_primes[PR_N] = {7, 11, 13, 17, 19};

static uint32_t pr_pow(uint32_t base, uint32_t exp, uint32_t mod)
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

/* Compute smallest primitive root of prime p. */
static uint32_t primitive_root(uint32_t p)
{
    uint32_t pm1 = p - 1;

    /* Factorise p-1 (trial division, small primes only) */
    uint32_t factors[16];
    uint32_t nf = 0;
    uint32_t rem = pm1;
    for (uint32_t f = 2; f * f <= rem; f++) {
        if (rem % f == 0) {
            factors[nf++] = f;
            while (rem % f == 0) rem /= f;
        }
    }
    if (rem > 1) factors[nf++] = rem;

    /* Try candidates g = 2, 3, ... */
    for (uint32_t g = 2; g < p; g++) {
        uint32_t ok = 1;
        for (uint32_t i = 0; i < nf; i++) {
            if (pr_pow(g, pm1 / factors[i], p) == 1) {
                ok = 0;
                break;
            }
        }
        if (ok) return g;
    }
    return 0; /* should not reach */
}

void test_primitive_root(void)
{
    uint32_t xor_roots = 0, sum_roots = 0;
    for (uint32_t i = 0; i < PR_N; i++) {
        uint32_t r = primitive_root(pr_primes[i]);
        xor_roots ^= r;
        sum_roots += r;
    }
    /* roots: {3,2,2,3,2}, xor=2, sum=12 */
    g_result = ((uint32_t)PR_N << 16) | ((xor_roots & 0xFFu) << 8) | (sum_roots & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_primitive_root();
    for (;;);
}
