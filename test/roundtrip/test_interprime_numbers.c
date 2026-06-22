#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 400u

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

/* Next prime strictly greater than n. */
static uint32_t next_prime(uint32_t n) {
    uint32_t c = n + 1u;
    while (!is_prime(c)) c++;
    return c;
}

/* An interprime is a composite number that is the average of two
   consecutive primes: n = (p + q) / 2 where p < n < q are consecutive primes. */
static void run_interprime_numbers(void) {
    uint32_t count = 0u;
    uint32_t ip_sum = 0u;
    uint32_t n;

    /* scan composites; for each find surrounding prime pair */
    for (n = 4u; n <= MAX_N; n++) {
        if (is_prime(n)) continue;
        /* find largest prime < n */
        uint32_t p = n - 1u;
        while (p >= 2u && !is_prime(p)) p--;
        if (p < 2u) continue;
        uint32_t q = next_prime(n);
        /* interprime: (p + q) must be even and equal 2*n */
        if ((p + q) == 2u * n) {
            count++;
            ip_sum += n % 251u;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = ip_sum % 251u;
    uint32_t metric_b = (ip_sum / 251u + 8u) % 251u;

    if (n_tests  == 0u) n_tests  = 13u;
    if (metric_a == 0u) metric_a = 23u;
    if (metric_b == 0u) metric_b = 9u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_interprime_numbers();
    while (1) {}
}
