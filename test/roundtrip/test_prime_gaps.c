/* test_prime_gaps.c
 * Purpose   : Compute gaps between consecutive primes up to PG_UPPER.
 *             Track the maximum gap and count of gaps (= number of primes - 1).
 *             For PG_UPPER=100: max_gap=8, gap_count=24.
 *
 * Algorithm : Build primes list via trial division, then sweep consecutive
 *             pairs to compute and compare gaps, tracking max.
 *
 * Distinctive decompiler idioms:
 *   1. Trial-division sieve: `d*d <= n` inner loop with break
 *   2. Consecutive-difference pattern: gap = prime[i+1] - prime[i]
 *   3. Running-max update: if gap > max_gap then max_gap = gap
 *
 * n_tests   = 100   (PG_UPPER, 0x64)
 * max_gap   = 8     (0x08)
 * gap_count = 24    (0x18)
 *
 * g_result = (PG_UPPER<<16) | (max_gap<<8) | gap_count = 0x640818
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define PG_UPPER   100u
#define PG_MAXPRIMES 32u

static uint32_t pg_is_prime(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if (n % 2u == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

void test_prime_gaps(void)
{
    uint32_t primes[PG_MAXPRIMES];
    uint32_t np = 0u;

    for (uint32_t n = 2u; n <= PG_UPPER && np < PG_MAXPRIMES; n++) {
        if (pg_is_prime(n)) {
            primes[np++] = n;
        }
    }

    uint32_t max_gap  = 0u;
    uint32_t gap_count = 0u;

    for (uint32_t i = 0u; i + 1u < np; i++) {
        uint32_t gap = primes[i + 1u] - primes[i];
        gap_count++;
        if (gap > max_gap) max_gap = gap;
    }
    /* max_gap=8=0x08, gap_count=24=0x18, PG_UPPER=100=0x64 → 0x640818 */
    g_result = (PG_UPPER << 16) | ((max_gap & 0xFFu) << 8) | (gap_count & 0xFFu);
}

void _start(void)
{
    test_prime_gaps();
    while (1) {}
}
