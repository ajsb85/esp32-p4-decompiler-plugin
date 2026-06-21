/* test_mersenne_exponents.c
 * Purpose   : Find Mersenne prime exponents p in [2..20] where 2^p - 1 is prime.
 *             Known Mersenne primes in this range: p=2,3,5,7,13,17,19 → 7 values.
 *             Sum of those exponents = 2+3+5+7+13+17+19 = 66.
 *
 * Algorithm : For each p in [2..ME_UPPER], compute M = (1<<p) - 1 and test primality
 *             by trial division.  If prime, increment count and add p to exp_sum.
 *
 * Distinctive decompiler idioms:
 *   1. Shift-based Mersenne construction: `M = (1u << p) - 1u`
 *   2. Trial-division primality up to sqrt, with early-out on even divisor
 *   3. Outer loop over candidate exponents with inner primality call
 *
 * n_tests   = 20    (ME_UPPER, 0x14)
 * me_count  = 7     (0x07)
 * exp_sum   = 66    (0x42)
 *
 * g_result = (ME_UPPER<<16) | (me_count<<8) | exp_sum = 0x140742
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define ME_UPPER 20u

static uint32_t me_is_prime(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

void test_mersenne_exponents(void)
{
    uint32_t me_count = 0u;
    uint32_t exp_sum  = 0u;

    for (uint32_t p = 2u; p <= ME_UPPER; p++) {
        uint32_t m = (1u << p) - 1u;
        if (me_is_prime(m)) {
            me_count++;
            exp_sum += p;
        }
    }
    /* count=7=0x07, exp_sum=66=0x42, ME_UPPER=20=0x14 → 0x140742 */
    g_result = (ME_UPPER << 16) | ((me_count & 0xFFu) << 8) | (exp_sum & 0xFFu);
}

void _start(void)
{
    test_mersenne_exponents();
    while (1) {}
}
