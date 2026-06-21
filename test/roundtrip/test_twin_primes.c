/* test_twin_primes.c
 * Purpose   : Find all twin-prime pairs (p, p+2) where both p and p+2 are
 *             prime, with p in [2..TP_UPPER-2]. Count pairs and sum first
 *             elements of each pair (mod 256).
 *             For TP_UPPER=100: pair_count=8, first_sum_mod=236.
 *
 * Algorithm : Trial-division primality test for each candidate p; if both
 *             p and p+2 are prime, increment count and add p to sum.
 *
 * Distinctive decompiler idioms:
 *   1. Trial-division primality test: inner loop `d*d <= n`, break on
 *      `n%d == 0`
 *   2. Twin-pair check: is_prime(p) && is_prime(p+2)
 *   3. Outer sweep accumulating pair_count and first_sum
 *
 * n_tests      = 100   (TP_UPPER, 0x64)
 * pair_count   = 8     (0x08)
 * first_sum_mod= 236   (0xEC)
 *
 * g_result = (TP_UPPER<<16) | (pair_count<<8) | first_sum_mod = 0x6408EC
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define TP_UPPER 100u

static uint32_t tp_is_prime(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if (n % 2u == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

void test_twin_primes(void)
{
    uint32_t pair_count = 0u;
    uint32_t first_sum  = 0u;

    for (uint32_t p = 2u; p + 2u <= TP_UPPER; p++) {
        if (tp_is_prime(p) && tp_is_prime(p + 2u)) {
            pair_count++;
            first_sum += p;
        }
    }
    /* pair_count=8=0x08, first_sum_mod=236=0xEC, TP_UPPER=100=0x64 → 0x6408EC */
    g_result = (TP_UPPER << 16) | ((pair_count & 0xFFu) << 8) | (first_sum & 0xFFu);
}

void _start(void)
{
    test_twin_primes();
    while (1) {}
}
