/*
 * test_necklace_counting.c
 * Necklace counting via Burnside's lemma + Euler's totient.
 *
 * Number of distinct binary necklaces of length n:
 *   N(n) = (1/n) * sum_{d | n} phi(d) * 2^(n/d)
 * where phi is Euler's totient function.
 *
 * We also count Lyndon words: primitive necklaces.
 * A necklace is primitive (Lyndon representative) if its period equals n.
 * Count via Mobius: L(n) = (1/n) * sum_{d | n} mu(n/d) * 2^d
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Euler totient: phi(n) = n * prod_{p|n}(1 - 1/p) */
static uint32_t nck_phi(uint32_t n) {
    uint32_t result = n;
    for (uint32_t p = 2u; p * p <= n; p++) {
        if (n % p == 0u) {
            while (n % p == 0u) n /= p;
            result -= result / p;
        }
    }
    if (n > 1u) result -= result / n;
    return result;
}

/* Mobius function: mu(n) */
static int32_t nck_mu(uint32_t n) {
    if (n == 1u) return 1;
    uint32_t factors = 0u;
    for (uint32_t p = 2u; p * p <= n; p++) {
        if (n % p == 0u) {
            factors++;
            n /= p;
            if (n % p == 0u) return 0; /* p^2 divides n */
        }
    }
    if (n > 1u) factors++;
    return (factors % 2u == 0u) ? 1 : -1;
}

/* 2^k mod 2^32 (just bit shift, k < 32) */
static uint32_t nck_pow2(uint32_t k) {
    if (k >= 32u) return 0u; /* overflow wraps to 0 for our purposes */
    return 1u << k;
}

/* Count distinct binary necklaces of length n using Burnside's lemma */
static uint32_t necklace_count_burnside(uint32_t n) {
    uint32_t total = 0u;
    for (uint32_t d = 1u; d <= n; d++) {
        if (n % d == 0u) {
            /* d divides n: contribute phi(d) * 2^(n/d) */
            total += nck_phi(d) * nck_pow2(n / d);
        }
    }
    return total / n;
}

/* Count primitive necklaces (Lyndon words) of length n */
static uint32_t lyndon_count(uint32_t n) {
    uint32_t total = 0u;
    for (uint32_t d = 1u; d <= n; d++) {
        if (n % d == 0u) {
            int32_t mu = nck_mu(n / d);
            if (mu > 0) total += nck_pow2(d);
            else if (mu < 0) total -= nck_pow2(d);
        }
    }
    return total / n;
}

/* Aperiodic necklace count = sum_{d|n} mu(d) * necklace_count(n/d)
 * For a simpler check: verify necklace_count(6) = 14. */
static uint32_t necklace_verify_n6(void) {
    /* n=6: divisors 1,2,3,6
     * phi(1)*2^6 + phi(2)*2^3 + phi(3)*2^2 + phi(6)*2^1
     * = 1*64 + 1*8 + 2*4 + 2*2 = 64+8+8+4 = 84
     * 84/6 = 14
     */
    return necklace_count_burnside(6u);
}

static uint32_t run_necklace_tests(void) {
    uint32_t n_tests = 0u;

    /*
     * Test 1: necklace_count(4) = 6.
     * divisors: phi(1)*2^4 + phi(2)*2^2 + phi(4)*2^1
     *         = 1*16 + 1*4 + 2*2 = 16+4+4 = 24; 24/4 = 6.
     */
    uint32_t nc4 = necklace_count_burnside(4u);
    n_tests++;
    /* nc4 == 6 */

    /*
     * Test 2: necklace_count(6) = 14.
     */
    uint32_t nc6 = necklace_verify_n6();
    n_tests++;
    /* nc6 == 14 */

    /*
     * Test 3: lyndon_count(6) = 9.
     * Primitive necklaces of length 6 over binary alphabet.
     * L(6) = (1/6)*(mu(1)*2^6 + mu(2)*2^3 + mu(3)*2^2 + mu(6)*2^1)
     *       = (1/6)*(64 - 8 - 4 + 2) = 54/6 = 9.
     */
    uint32_t lc6 = lyndon_count(6u);
    n_tests++;
    /* lc6 == 9 */

    /*
     * Pack:
     * n_tests = 3 = 0x03
     * metric_a: nc4=6, nc6=14 -> (nc4 << 4) | (nc6 & 0xF) = (6<<4)|(14&0xF) = 96|14=110=0x6E
     * metric_b: lc6=9, pack as 0x40 | lc6 = 0x49 = 73
     * Result = (3<<16)|(0x6E<<8)|0x49 = 0x036E49
     * Bytes: 0x03, 0x6E, 0x49 — non-zero, distinct.
     */
    uint32_t metric_a = (nc4 << 4) | (nc6 & 0xFu);
    uint32_t metric_b = 0x40u | (lc6 & 0x3Fu);
    return (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_necklace_tests();
    while (1) {}
}
