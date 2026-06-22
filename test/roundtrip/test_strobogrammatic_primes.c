/* test_strobogrammatic_primes.c — strobogrammatic primes
 * A strobogrammatic number looks the same when rotated 180°.
 * Valid digits: 0,1,6,8,9 (mapping: 0↔0, 1↔1, 6↔9, 8↔8, 9↔6).
 * We check each number up to 200: is it strobogrammatic AND prime?
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 200u

/* Return rotated-180 equivalent of digit, or 0xFF if invalid. */
static uint32_t rot_digit(uint32_t d) {
    if (d == 0u) return 0u;
    if (d == 1u) return 1u;
    if (d == 6u) return 9u;
    if (d == 8u) return 8u;
    if (d == 9u) return 6u;
    return 0xFFu;  /* invalid */
}

/* Extract digits into buf (least-significant first), return count. */
static uint32_t get_digits(uint32_t n, uint32_t *buf) {
    uint32_t len = 0u;
    if (n == 0u) { buf[0] = 0u; return 1u; }
    while (n > 0u) {
        buf[len++] = n % 10u;
        n /= 10u;
    }
    return len;
}

static uint32_t is_strobogrammatic(uint32_t n) {
    uint32_t digits[10];
    uint32_t len = get_digits(n, digits);
    uint32_t lo = 0u, hi = len;
    while (lo < hi) {
        hi--;
        uint32_t r = rot_digit(digits[lo]);
        if (r == 0xFFu)          return 0u;
        if (r != digits[hi])     return 0u;
        lo++;
    }
    return 1u;
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

static void run_strobogrammatic_primes(void) {
    uint32_t count  = 0u;
    uint32_t sp_sum = 0u;
    uint32_t n;

    for (n = 2u; n <= MAX_N; n++) {
        if (is_prime(n) && is_strobogrammatic(n)) {
            count++;
            sp_sum += n;
        }
    }

    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = sp_sum % 251u;
    uint32_t metric_b = (sp_sum / 251u + 3u) % 251u;

    if (n_tests  == 0u) n_tests  = 6u;
    if (metric_a == 0u) metric_a = 17u;
    if (metric_b == 0u) metric_b = 5u;

    if (metric_a == n_tests)  metric_a = (metric_a % 250u) + 1u;
    if (metric_b == n_tests)  metric_b = (metric_b % 249u) + 2u;
    if (metric_b == metric_a) metric_b = (metric_b % 248u) + 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_strobogrammatic_primes();
    while (1) {}
}
