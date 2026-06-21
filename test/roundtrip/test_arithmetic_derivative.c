/* test_arithmetic_derivative.c
 * Purpose   : Compute the arithmetic derivative a'(n) for each n in [1..60].
 *             Rules: a'(1)=0, a'(p)=1 for prime p,
 *             a'(p^k) = k*p^(k-1), extended by product rule a'(mn) = a'(m)*n + m*a'(n).
 *             Equivalently: a'(n) = n * sum(e_i / p_i) over the prime factorisation.
 *             Count numbers n in [2..60] where a'(n) > n (17 such numbers),
 *             and compute sum of all a'(n) for n in [1..60] mod 256 (= 87).
 *
 * Algorithm : Trial division to factorise n; accumulate n/p for each prime power.
 *
 * Distinctive decompiler idioms:
 *   1. Trial-division factorisation with quotient accumulator: result += n/d
 *   2. Residual prime factor check after trial loop
 *   3. Outer loop comparing derivative to original value for "exceed" count
 *
 * n_tests   = 60   (0x3C — upper limit)
 * count     = 17   (0x11 — numbers where a'(n) > n)
 * sum_mod   = 87   (0x57 — total sum of a'(n) for n in [1..60] mod 256)
 *
 * g_result  = (60<<16) | (17<<8) | 87 = 0x3C1157
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define AD_UPPER 60u

static uint32_t ad_is_prime(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n < 4u) return 1u;
    if (n % 2u == 0u || n % 3u == 0u) return 0u;
    uint32_t i = 5u;
    while (i * i <= n) {
        if (n % i == 0u || n % (i + 2u) == 0u) return 0u;
        i += 6u;
    }
    return 1u;
}

static uint32_t arith_deriv(uint32_t n)
{
    if (n <= 1u) return 0u;
    if (ad_is_prime(n)) return 1u;
    uint32_t result = 0u;
    uint32_t temp   = n;
    uint32_t d      = 2u;
    while (d * d <= temp) {
        while (temp % d == 0u) {
            result += n / d;   /* contribution: n/p for each prime factor p */
            temp   /= d;
        }
        d++;
    }
    if (temp > 1u) {
        result += n / temp;    /* residual prime factor */
    }
    return result;
}

void test_arithmetic_derivative(void)
{
    uint32_t count_exceed = 0u;
    uint32_t total_sum    = 0u;

    for (uint32_t i = 1u; i <= AD_UPPER; i++) {
        uint32_t d = arith_deriv(i);
        total_sum += d;
        if (i >= 2u && d > i) count_exceed++;
    }

    /* count_exceed=17=0x11, total_sum%256=87=0x57, AD_UPPER=60=0x3C
     * g_result = (60<<16)|(17<<8)|87 = 0x3C1157 */
    g_result = (AD_UPPER << 16) | ((count_exceed & 0xFFu) << 8) | (total_sum & 0xFFu);
}

void _start(void)
{
    test_arithmetic_derivative();
    while (1) {}
}
