/* test_lucky_primes.c — lucky numbers sieve + primes that are also lucky
 * Lucky numbers: start with naturals, sieve by position iteratively.
 * Lucky primes: numbers that are both lucky and prime.
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 300u
#define SIEVE_SIZE 300u

static uint32_t lucky[SIEVE_SIZE];
static uint32_t lucky_sz;

static void build_lucky(void) {
    uint32_t i;
    /* Initialize with odd numbers: 1,3,5,7,9,... */
    lucky_sz = 0u;
    for (i = 1u; i <= MAX_N; i += 2u) {
        lucky[lucky_sz++] = i;
    }
    /* Sieve: step through lucky[1], lucky[2], ... */
    uint32_t step = 1u; /* start at index 1 (value=3) */
    while (step < lucky_sz) {
        uint32_t sieve_val = lucky[step];
        /* Remove every sieve_val-th element */
        uint32_t new_sz = 0u;
        for (i = 0u; i < lucky_sz; i++) {
            if ((i + 1u) % sieve_val != 0u) {
                lucky[new_sz++] = lucky[i];
            }
        }
        lucky_sz = new_sz;
        step++;
        if (step >= lucky_sz) break;
    }
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

static uint32_t is_lucky(uint32_t n) {
    uint32_t lo = 0u, hi = lucky_sz;
    while (lo < hi) {
        uint32_t mid = (lo + hi) >> 1u;
        if (lucky[mid] == n) return 1u;
        else if (lucky[mid] < n) lo = mid + 1u;
        else hi = mid;
    }
    return 0u;
}

static void run_lucky_primes(void) {
    build_lucky();

    uint32_t count = 0u;
    uint32_t lp_sum = 0u;
    uint32_t n;

    /* Find lucky primes up to 250 */
    for (n = 2u; n <= 250u; n++) {
        if (is_prime(n) && is_lucky(n)) {
            count++;
            lp_sum += n;
        }
    }

    /* Lucky primes <= 250: 3,7,13,31,37,43,67,73,79,127,151,163,193,211 ...
     * We use computed values. */
    uint32_t n_tests  = count & 0xFFu;
    uint32_t metric_a = lp_sum % 251u;
    uint32_t metric_b = lucky_sz % 251u;

    if (metric_a == 0u) metric_a = 7u;
    if (metric_b == 0u) metric_b = 3u;

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_lucky_primes();
    while (1) {}
}
