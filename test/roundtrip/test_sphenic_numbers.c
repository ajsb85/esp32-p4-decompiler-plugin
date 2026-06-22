/* test_sphenic_numbers.c — sphenic numbers
 * A sphenic number is a positive integer that is the product of exactly three
 * distinct prime factors (e.g. 30 = 2*3*5, 42 = 2*3*7, 66 = 2*3*11).
 * We scan n=2..300, count sphenic numbers, and accumulate their sum.
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 300u

/* Count distinct prime factors of n (without multiplicity).
 * Returns the number of distinct primes dividing n. */
static uint32_t count_distinct_prime_factors(uint32_t n) {
    uint32_t count = 0u;
    uint32_t d;
    if (n < 2u) return 0u;
    /* Check factor 2 */
    if (n % 2u == 0u) {
        count++;
        while (n % 2u == 0u) n /= 2u;
    }
    /* Check odd factors */
    for (d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) {
            count++;
            while (n % d == 0u) n /= d;
        }
    }
    if (n > 1u) count++;
    return count;
}

/* Check if n is squarefree (no prime factor appears more than once). */
static uint32_t is_squarefree(uint32_t n) {
    uint32_t d;
    if (n < 2u) return 1u;
    if (n % 4u == 0u) return 0u;
    for (d = 3u; d * d <= n; d += 2u) {
        if (n % (d * d) == 0u) return 0u;
    }
    return 1u;
}

static void run_sphenic_numbers(void) {
    uint32_t count   = 0u;
    uint32_t sp_sum  = 0u;
    uint32_t n;

    for (n = 2u; n <= MAX_N; n++) {
        if (is_squarefree(n) && count_distinct_prime_factors(n) == 3u) {
            count++;
            sp_sum += n;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = sp_sum % 251u;
    uint32_t metric_b = (sp_sum / 251u + 5u) % 251u;

    if (n_tests  == 0u) n_tests  = 7u;
    if (metric_a == 0u) metric_a = 11u;
    if (metric_b == 0u) metric_b = 8u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_sphenic_numbers();
    while (1) {}
}
