/*
 * test_blum_integers.c
 * Blum integers: products n = p*q of two distinct primes both ≡ 3 (mod 4).
 * Used in Blum-Blum-Shub PRNG. E.g. 21=3*7, 33=3*11, 57=3*19, 77=7*11, ...
 * Self-contained, 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Trial division primality test */
static uint32_t is_prime(uint32_t n) {
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t i = 3u; i * i <= n; i += 2u) {
        if (n % i == 0u) return 0u;
    }
    return 1u;
}

/*
 * n is a Blum integer if:
 *   n = p * q, p != q, both prime, p ≡ 3 (mod 4), q ≡ 3 (mod 4).
 */
static uint32_t is_blum(uint32_t n) {
    if (n < 21u) return 0u;
    /* Find smallest prime factor p */
    uint32_t p = 0u;
    for (uint32_t i = 2u; i * i <= n; i++) {
        if (n % i == 0u) { p = i; break; }
    }
    if (p == 0u) return 0u;      /* n is prime, not a semiprime */
    uint32_t q = n / p;
    if (q == p) return 0u;       /* must be distinct */
    if (!is_prime(p)) return 0u;
    if (!is_prime(q)) return 0u;
    if ((p % 4u) != 3u) return 0u;
    if ((q % 4u) != 3u) return 0u;
    return 1u;
}

void _start(void) {
    /*
     * Count Blum integers in [1, 500] and accumulate a checksum.
     */
    uint32_t count = 0u;
    uint32_t bsum  = 0u;

    for (uint32_t n = 21u; n <= 500u; n++) {
        if (is_blum(n)) {
            count++;
            bsum += n & 0xFFu;
        }
    }

    uint32_t n_tests  = 99u;              /* 0x63 */
    uint32_t metric_a = count & 0xFFu;    /* non-zero */
    uint32_t metric_b = bsum  & 0xFFu;    /* non-zero, distinct */

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
