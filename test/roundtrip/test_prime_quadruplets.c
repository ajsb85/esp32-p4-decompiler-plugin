#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 500u

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

/* A prime quadruplet is (p, p+2, p+6, p+8) all prime. */
static void run_prime_quadruplets(void) {
    uint32_t count = 0u;
    uint32_t quad_sum = 0u;
    uint32_t p;

    for (p = 5u; p + 8u <= MAX_N; p++) {
        if (is_prime(p) && is_prime(p + 2u) && is_prime(p + 6u) && is_prime(p + 8u)) {
            count++;
            quad_sum += p % 251u;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = quad_sum % 251u;
    uint32_t metric_b = (quad_sum / 251u + 7u) % 251u;

    if (n_tests  == 0u) n_tests  = 11u;
    if (metric_a == 0u) metric_a = 17u;
    if (metric_b == 0u) metric_b = 9u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_prime_quadruplets();
    while (1) {}
}
