/* test_ore_numbers.c — Ore numbers (harmonic divisor numbers)
 * An Ore number (harmonic divisor number) is a positive integer n whose
 * harmonic mean of divisors is an integer.  The harmonic mean of divisors
 * equals  n * d(n) / sigma(n),  where d(n) is the count of divisors and
 * sigma(n) is their sum.  The number is harmonic iff n*d(n) % sigma(n) == 0.
 * Known Ore numbers up to 300: 1, 6, 28, 140, 270.
 * We scan n=1..300, collect them, and compute count + sum.
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 300u

/* Compute (divisor_count, divisor_sum) for n. */
static void divisor_stats(uint32_t n, uint32_t *d_count, uint32_t *d_sum) {
    uint32_t cnt = 0u;
    uint32_t sum = 0u;
    uint32_t i;
    for (i = 1u; i * i <= n; i++) {
        if (n % i == 0u) {
            cnt++;
            sum += i;
            if (i != n / i) {
                cnt++;
                sum += n / i;
            }
        }
    }
    *d_count = cnt;
    *d_sum   = sum;
}

static void run_ore_numbers(void) {
    uint32_t count   = 0u;
    uint32_t ore_sum = 0u;
    uint32_t n;

    for (n = 1u; n <= MAX_N; n++) {
        uint32_t dc, ds;
        divisor_stats(n, &dc, &ds);
        /* Harmonic divisor: n * dc divisible by ds */
        if (ds > 0u && (n * dc) % ds == 0u) {
            count++;
            ore_sum += n;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = ore_sum % 251u;
    uint32_t metric_b = (ore_sum / 251u + 3u) % 251u;

    if (n_tests  == 0u) n_tests  = 5u;
    if (metric_a == 0u) metric_a = 9u;
    if (metric_b == 0u) metric_b = 4u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_ore_numbers();
    while (1) {}
}
