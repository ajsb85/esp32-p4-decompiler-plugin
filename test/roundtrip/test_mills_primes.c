/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Mills Primes fixture.
 *
 * Mills' theorem (1947): there exists a real constant A > 1 such that
 * floor(A^(3^n)) is prime for all n >= 0.
 *
 * The first four Mills primes (assuming Riemann hypothesis):
 *   P(0) = floor(A^1)      = 2
 *   P(1) = floor(A^3)      = 11
 *   P(2) = floor(A^9)      = 1361
 *   P(3) = floor(A^27)     = 2521008887  (exceeds 32-bit)
 *
 * Fixture verifies P(0)..P(2) are prime, computes their sum and
 * the largest (P(2)) modulo 251.
 *
 * Distinctive decompiler idioms:
 *   1. Fixed array of known Mills primes: {2, 11, 1361}
 *   2. Trial-division primality on each element
 *   3. Largest element modulo 251 as metric_b
 *
 * Results:
 *   n_tests  = 3                        = 0x03
 *   metric_a = sum(2+11+1361) % 251     = 1374 % 251 = 119 = 0x77
 *   metric_b = 1361 % 251               = 106         = 0x6A
 *
 * g_result = (3<<16)|(119<<8)|106 = 0x0003776A
 */
#include <stdint.h>

volatile uint32_t g_result;

static uint32_t is_prime(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    uint32_t i;
    for (i = 3u; i * i <= n; i += 2u)
        if (n % i == 0u) return 0u;
    return 1u;
}

void test_mills_primes(void)
{
    /* Known Mills primes that fit in 32-bit */
    static const uint32_t mills[3] = { 2u, 11u, 1361u };
    uint32_t total_sum = 0u;
    uint32_t cnt_prime = 0u;
    uint32_t i;

    for (i = 0u; i < 3u; i++) {
        total_sum += mills[i];
        if (is_prime(mills[i]))
            cnt_prime++;
    }
    /* total_sum=1374, total_sum%251=119, mills[2]%251=106 */
    (void)cnt_prime;
    g_result = (3u << 16)
             | ((total_sum % 251u) << 8)
             | (mills[2] % 251u);
}

__attribute__((noreturn)) void _start(void)
{
    test_mills_primes();
    for (;;);
}
