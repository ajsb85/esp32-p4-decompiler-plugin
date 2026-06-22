/* test_happy_primes.c — happy primes (numbers that are both happy and prime)
 * Happy number: repeatedly sum squares of digits; reaches 1 → happy.
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N    200u
#define MAX_ITER 200u

static uint32_t digit_sq_sum(uint32_t n) {
    uint32_t s = 0u;
    while (n > 0u) {
        uint32_t d = n % 10u;
        s += d * d;
        n /= 10u;
    }
    return s;
}

static uint32_t is_happy(uint32_t n) {
    uint32_t i;
    for (i = 0u; i < MAX_ITER; i++) {
        n = digit_sq_sum(n);
        if (n == 1u) return 1u;
        if (n == 4u) return 0u;  /* known cycle entry */
    }
    return 0u;
}

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

static void run_happy_primes(void) {
    uint32_t count  = 0u;
    uint32_t hp_sum = 0u;
    uint32_t n;

    for (n = 2u; n <= MAX_N; n++) {
        if (is_prime(n) && is_happy(n)) {
            count++;
            hp_sum += n;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = hp_sum % 251u;
    uint32_t metric_b = (hp_sum / 251u + 1u) % 251u;

    if (n_tests  == 0u) n_tests  = 7u;
    if (metric_a == 0u) metric_a = 13u;
    if (metric_b == 0u) metric_b = 5u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_happy_primes();
    while (1) {}
}
