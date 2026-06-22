/* test_catalan_primes.c — Catalan numbers that are prime
 * Catalan(n) = C(2n,n)/(n+1).  Check which are prime.
 * Only Catalan(2)=2 and Catalan(3)=5 are prime.
 * We search Catalan(n) for n=0..12 (values fit in 32-bit),
 * count primes, and accumulate a checksum.
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_CAT 13u

/* Precomputed catalan(0)..catalan(12):
 * 1,1,2,5,14,42,132,429,1430,4862,16796,58786,208012 */
static const uint32_t catalan_vals[MAX_CAT] = {
    1u, 1u, 2u, 5u, 14u, 42u, 132u, 429u,
    1430u, 4862u, 16796u, 58786u, 208012u
};

static uint32_t is_prime(uint32_t n) {
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if (n % 2u == 0u) return 0u;
    uint32_t i;
    for (i = 3u; i * i <= n; i += 2u) {
        if (n % i == 0u) return 0u;
    }
    return 1u;
}

static void run_catalan_primes(void) {
    uint32_t prime_count = 0u;
    uint32_t cat_sum     = 0u;
    uint32_t idx_sum     = 0u;
    uint32_t i;

    for (i = 0u; i < MAX_CAT; i++) {
        if (is_prime(catalan_vals[i])) {
            prime_count++;
            idx_sum  += i;
            cat_sum  += catalan_vals[i];
        }
    }

    uint32_t n_tests  = prime_count & 0xFFu;
    uint32_t metric_a = cat_sum % 251u;
    uint32_t metric_b = (idx_sum + MAX_CAT) % 251u;

    if (n_tests  == 0u) n_tests  = 4u;
    if (metric_a == 0u) metric_a = 9u;
    if (metric_b == 0u) metric_b = 3u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_catalan_primes();
    while (1) {}
}
