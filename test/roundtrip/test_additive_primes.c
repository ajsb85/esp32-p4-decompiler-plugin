/* test_additive_primes.c — additive primes
 * An additive prime is a prime number whose decimal digit sum is also prime.
 * Examples: 2, 3, 5, 7, 11 (1+1=2 prime), 23 (2+3=5 prime), 29 (2+9=11 prime).
 * We scan n=2..300, collect additive primes, then compute count and sum.
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 300u

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

/* Compute sum of decimal digits of n. */
static uint32_t digit_sum(uint32_t n) {
    uint32_t s = 0u;
    while (n > 0u) {
        s += n % 10u;
        n /= 10u;
    }
    return s;
}

static void run_additive_primes(void) {
    uint32_t count  = 0u;
    uint32_t ap_sum = 0u;
    uint32_t n;

    for (n = 2u; n <= MAX_N; n++) {
        if (is_prime(n) && is_prime(digit_sum(n))) {
            count++;
            ap_sum += n;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = ap_sum % 251u;
    uint32_t metric_b = (ap_sum / 251u + 4u) % 251u;

    if (n_tests  == 0u) n_tests  = 9u;
    if (metric_a == 0u) metric_a = 13u;
    if (metric_b == 0u) metric_b = 6u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_additive_primes();
    while (1) {}
}
