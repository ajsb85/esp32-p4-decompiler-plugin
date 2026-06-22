/* test_truncatable_primes.c — left- and right-truncatable primes
 * Left-truncatable: removing digits from the left leaves primes.
 * Right-truncatable: removing digits from the right leaves primes.
 * There are exactly 83 right-truncatable primes and 4260 left-truncatable primes (finite sets).
 * We test small sets up to 1000.
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

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

/* Right-truncatable: n, n/10, n/100 ... all prime (until single digit) */
static uint32_t is_right_truncatable(uint32_t n) {
    if (n < 2u) return 0u;
    uint32_t t = n;
    while (t > 0u) {
        if (!is_prime(t)) return 0u;
        t /= 10u;
    }
    return 1u;
}

/* Left-truncatable: n, n%10^(d-1), n%10^(d-2) ... all prime */
static uint32_t num_digits(uint32_t n) {
    if (n < 10u) return 1u;
    if (n < 100u) return 2u;
    if (n < 1000u) return 3u;
    if (n < 10000u) return 4u;
    return 5u;
}

static uint32_t pow10_table[6] = {1u, 10u, 100u, 1000u, 10000u, 100000u};

static uint32_t is_left_truncatable(uint32_t n) {
    if (n < 2u) return 0u;
    /* No zeros allowed in digits */
    uint32_t tmp = n;
    while (tmp > 0u) {
        if (tmp % 10u == 0u) return 0u;
        tmp /= 10u;
    }
    uint32_t d = num_digits(n);
    uint32_t i;
    for (i = d; i >= 1u; i--) {
        uint32_t truncated = n % pow10_table[i];
        if (!is_prime(truncated)) return 0u;
    }
    return 1u;
}

static void run_truncatable_primes(void) {
    uint32_t right_count = 0u;
    uint32_t left_count  = 0u;
    uint32_t right_sum   = 0u;
    uint32_t n;

    for (n = 2u; n <= 999u; n++) {
        if (is_right_truncatable(n)) {
            right_count++;
            right_sum += n;
        }
        if (is_left_truncatable(n)) {
            left_count++;
        }
    }

    /* right_count up to 999: 2,3,5,7,23,29,31,37,53,59,71,73,79,233,239,293,311,313,317,
     *   373,379,593,599,719,733,739,797,...
     * We just use the computed values. Pack them compactly. */
    uint32_t n_tests  = right_count & 0xFFu;
    uint32_t metric_a = right_sum % 251u;
    uint32_t metric_b = left_count % 251u;

    /* Ensure metric_b != 0 (left_count guaranteed > 0) */
    if (metric_b == 0u) metric_b = 1u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_truncatable_primes();
    while (1) {}
}
