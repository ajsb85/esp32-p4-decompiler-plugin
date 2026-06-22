/* test_repunit_primes.c — repunit primes
 * A repunit R(n) is a number consisting of n repeated '1' digits in base 10:
 *   R(1)=1, R(2)=11, R(3)=111, R(4)=1111, ...
 * R(n) is prime only when n itself is prime (necessary but not sufficient).
 * We test R(2)=11, R(19), R(23) for primality directly with trial division.
 * To keep all values in 32-bit, we cap R(n) at 9 digits (n <= 9).
 * Scan n=2..9: build R(n) = (10^n - 1) / 9 using 32-bit multiply, test primality.
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_REPUNIT_LEN 9u

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

/* Build R(len) = 111...1 (len ones). Works for len <= 9 in 32-bit. */
static uint32_t build_repunit(uint32_t len) {
    uint32_t r = 0u;
    uint32_t i;
    for (i = 0u; i < len; i++) {
        r = r * 10u + 1u;
    }
    return r;
}

static void run_repunit_primes(void) {
    uint32_t count   = 0u;
    uint32_t rp_sum  = 0u;
    uint32_t len;

    for (len = 2u; len <= MAX_REPUNIT_LEN; len++) {
        uint32_t r = build_repunit(len);
        if (is_prime(r)) {
            count++;
            rp_sum += r;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = rp_sum % 251u;
    uint32_t metric_b = (rp_sum / 251u + 5u) % 251u;

    if (n_tests  == 0u) n_tests  = 8u;
    if (metric_a == 0u) metric_a = 23u;
    if (metric_b == 0u) metric_b = 7u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_repunit_primes();
    while (1) {}
}
