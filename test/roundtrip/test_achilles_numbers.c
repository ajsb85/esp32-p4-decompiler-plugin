#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 1000u

/* Return largest exponent in prime factorization of n for prime p. */
static uint32_t prime_exp(uint32_t n, uint32_t p) {
    uint32_t e = 0u;
    while (n % p == 0u) {
        e++;
        n /= p;
    }
    return e;
}

/* An Achilles number is powerful (every prime factor appears >= squared)
   but not a perfect power.
   powerful: for every prime p | n, p^2 | n.
   not a perfect power: no k>=2 with m^k = n. */
static uint32_t is_powerful(uint32_t n) {
    if (n < 2u) return 0u;
    uint32_t m = n;
    uint32_t d;
    if (m % 2u == 0u) {
        if (prime_exp(m, 2u) < 2u) return 0u;
        while (m % 2u == 0u) m /= 2u;
    }
    for (d = 3u; d * d <= m; d += 2u) {
        if (m % d == 0u) {
            if (prime_exp(m, d) < 2u) return 0u;
            while (m % d == 0u) m /= d;
        }
    }
    return 1u;
}

/* Check if n = m^k for some integers m>=2, k>=2. */
static uint32_t is_perfect_power(uint32_t n) {
    if (n < 4u) return 0u;
    /* try exponents k from 2 up */
    uint32_t k;
    for (k = 2u; (1u << k) <= n; k++) {
        /* find integer k-th root via newton or simple iteration */
        uint32_t r = 2u;
        while (1) {
            /* r^k <= n? compute r^k carefully */
            uint32_t pw = 1u;
            uint32_t i;
            uint32_t overflow = 0u;
            for (i = 0u; i < k; i++) {
                if (pw > n / r + 1u) { overflow = 1u; break; }
                pw *= r;
                if (pw > n + 1u) { overflow = 1u; break; }
            }
            if (!overflow && pw == n) return 1u;
            if (overflow || pw > n) break;
            r++;
        }
    }
    return 0u;
}

static void run_achilles_numbers(void) {
    uint32_t count   = 0u;
    uint32_t ach_sum = 0u;
    uint32_t n;

    for (n = 2u; n <= MAX_N; n++) {
        if (is_powerful(n) && !is_perfect_power(n)) {
            count++;
            ach_sum += n % 251u;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = ach_sum % 251u;
    uint32_t metric_b = (ach_sum / 251u + 6u) % 251u;

    if (n_tests  == 0u) n_tests  = 11u;
    if (metric_a == 0u) metric_a = 17u;
    if (metric_b == 0u) metric_b = 7u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_achilles_numbers();
    while (1) {}
}
