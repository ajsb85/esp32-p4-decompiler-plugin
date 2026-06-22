/* test_hoax_numbers.c — hoax numbers
 * A hoax number is a composite number whose digit sum equals the sum of digits
 * of all its distinct prime factors.
 * Example: 22 = 2*11; digit_sum(22)=4, digit_sum(2)+digit_sum(11)=2+2=4 => hoax.
 * We scan n=2..300, collect hoax numbers, compute count and sum.
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 300u

/* Sum of decimal digits of n. */
static uint32_t digit_sum(uint32_t n) {
    uint32_t s = 0u;
    if (n == 0u) return 0u;
    while (n > 0u) {
        s += n % 10u;
        n /= 10u;
    }
    return s;
}

/* Sum of digits of all distinct prime factors of n. */
static uint32_t prime_factor_digit_sum(uint32_t n) {
    uint32_t s = 0u;
    uint32_t d;
    if (n < 2u) return 0u;
    if (n % 2u == 0u) {
        s += digit_sum(2u);
        while (n % 2u == 0u) n /= 2u;
    }
    for (d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) {
            s += digit_sum(d);
            while (n % d == 0u) n /= d;
        }
    }
    if (n > 1u) s += digit_sum(n);
    return s;
}

/* Check if n is prime. */
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

static void run_hoax_numbers(void) {
    uint32_t count    = 0u;
    uint32_t hoax_sum = 0u;
    uint32_t n;

    for (n = 2u; n <= MAX_N; n++) {
        /* Must be composite */
        if (is_prime(n)) continue;
        if (digit_sum(n) == prime_factor_digit_sum(n)) {
            count++;
            hoax_sum += n;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = hoax_sum % 251u;
    uint32_t metric_b = (hoax_sum / 251u + 6u) % 251u;

    if (n_tests  == 0u) n_tests  = 11u;
    if (metric_a == 0u) metric_a = 17u;
    if (metric_b == 0u) metric_b = 7u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_hoax_numbers();
    while (1) {}
}
