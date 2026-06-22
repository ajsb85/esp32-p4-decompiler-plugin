/* test_hyperperfect_numbers.c
 * Purpose   : Find k-hyperperfect numbers in range 2..300
 * Algorithm : A number n is k-hyperperfect if n = 1 + k * S(n), where
 *             S(n) = sum of proper divisors of n excluding 1 and n itself.
 *             (k=1 gives ordinary perfect numbers.)
 *             For each n: compute S(n), check if (n-1) is divisible by S(n),
 *             and if so k = (n-1)/S(n) >= 1.
 * Input     : range 2..300 (n_tests = 299)
 * Expected  : Hyperperfect numbers in 2..300:
 *               n=6  (k=1, perfect), n=21 (k=2), n=28 (k=1, perfect)
 *             count = 3, hsum = 6+21+28 = 55
 *             metric_a = count & 0xFF = 3
 *             metric_b = hsum % 251 = 55
 *             n_tests  = 299
 * g_result  = (299<<16)|(3<<8)|55 = 0x12B0337
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* Sum of proper divisors of n, excluding 1 and n */
static uint32_t sigma_s(uint32_t n) {
    if (n < 4u) return 0u;
    uint32_t s = 0u;
    for (uint32_t d = 2u; d < n; d++) {
        if (n % d == 0u) s += d;
    }
    return s;
}

static uint32_t is_hyperperfect(uint32_t n) {
    if (n < 2u) return 0u;
    uint32_t s = sigma_s(n);
    if (s == 0u) return 0u;
    if ((n - 1u) % s != 0u) return 0u;
    uint32_t k = (n - 1u) / s;
    return (k >= 1u) ? 1u : 0u;
}

void _start(void) {
    uint32_t n_tests = 299u;
    uint32_t count   = 0u;
    uint32_t hsum    = 0u;

    for (uint32_t n = 2u; n <= n_tests + 1u; n++) {
        if (is_hyperperfect(n)) {
            count++;
            hsum += n;
        }
    }

    /* n_tests=299, count=3, hsum%251=55 => 0x12B0337 */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = hsum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
