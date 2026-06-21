/* test_cousin_primes.c
 * Purpose   : Count cousin prime pairs (p, p+4) where both p and p+4 are prime,
 *             searching p from 2 up to CP_UPPER=100.
 *             Pairs found: (3,7),(7,11),(13,17),(19,23),(37,41),(43,47),(67,71),(79,83)
 *             → cp_count=8, last_p=79.
 *
 * Algorithm : For each p in [2, CP_UPPER-4], test primality of p and p+4
 *             via trial division. If both prime, increment counter and record p.
 *
 * Distinctive decompiler idioms:
 *   1. Trial-division primality: `d*d <= n` inner loop with early return
 *   2. Pair test: `is_prime(p) && is_prime(p+4)` guard
 *   3. Running-last update: track p on each hit
 *
 * n_tests  = 100  (CP_UPPER, 0x64)
 * cp_count = 8    (          0x08)
 * last_p   = 79   (          0x4F)
 *
 * g_result = (CP_UPPER<<16) | (cp_count<<8) | last_p = 0x64084F
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define CP_UPPER  100u

static uint32_t cp_is_prime(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if (n % 2u == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

void test_cousin_primes(void)
{
    uint32_t cp_count = 0u;
    uint32_t last_p   = 0u;

    for (uint32_t p = 2u; p + 4u <= CP_UPPER; p++) {
        if (cp_is_prime(p) && cp_is_prime(p + 4u)) {
            cp_count++;
            last_p = p;
        }
    }
    /* cp_count=8=0x08, last_p=79=0x4F, CP_UPPER=100=0x64 → 0x64084F */
    g_result = (CP_UPPER << 16) | ((cp_count & 0xFFu) << 8) | (last_p & 0xFFu);
}

void _start(void)
{
    test_cousin_primes();
    while (1) {}
}
