/* test_undulating_primes.c — undulating primes
 * An undulating number has digits that strictly alternate up-down-up or
 * down-up-down (adjacent digits differ and the pattern oscillates).
 * Formally: for digits d[0]..d[k], every pair of adjacent digits differs,
 * and d[0]!=d[1], d[1]!=d[2] with sign(d[i]-d[i-1]) != sign(d[i+1]-d[i]).
 * Single-digit and two-digit numbers are excluded (need at least 3 digits).
 * We scan primes up to 400 and collect those that are undulating.
 * 32-bit only, no stdlib.
 */
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

/* Extract decimal digits into buf (most-significant first), return count. */
static uint32_t get_digits_msf(uint32_t n, uint32_t *buf) {
    uint32_t tmp[10];
    uint32_t len = 0u;
    if (n == 0u) { buf[0] = 0u; return 1u; }
    while (n > 0u) {
        tmp[len++] = n % 10u;
        n /= 10u;
    }
    uint32_t i;
    for (i = 0u; i < len; i++)
        buf[i] = tmp[len - 1u - i];
    return len;
}

/* An undulating number must have >= 3 digits and digits that alternate
 * strictly: each consecutive difference flips sign. */
static uint32_t is_undulating(uint32_t n) {
    uint32_t digits[10];
    uint32_t len = get_digits_msf(n, digits);
    if (len < 3u) return 0u;

    uint32_t i;
    for (i = 1u; i < len; i++) {
        if (digits[i] == digits[i - 1u]) return 0u;
    }
    /* Check alternation: direction must flip at each interior digit. */
    for (i = 1u; i + 1u < len; i++) {
        uint32_t prev_up = (digits[i]     > digits[i - 1u]) ? 1u : 0u;
        uint32_t next_up = (digits[i + 1u] > digits[i])     ? 1u : 0u;
        if (prev_up == next_up) return 0u;
    }
    return 1u;
}

static void run_undulating_primes(void) {
    uint32_t count  = 0u;
    uint32_t up_sum = 0u;
    uint32_t n;

    for (n = 2u; n <= MAX_N; n++) {
        if (is_prime(n) && is_undulating(n)) {
            count++;
            up_sum += n;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = up_sum % 251u;
    uint32_t metric_b = (up_sum / 251u + 3u) % 251u;

    if (n_tests  == 0u) n_tests  = 7u;
    if (metric_a == 0u) metric_a = 19u;
    if (metric_b == 0u) metric_b = 5u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_undulating_primes();
    while (1) {}
}
