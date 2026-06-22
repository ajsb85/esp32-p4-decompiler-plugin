/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Emirp Primes fixture.
 *
 * An emirp is a prime whose digit-reversal is also prime and different
 * from itself (non-palindromic).
 *
 * First 15 emirps: 13, 17, 31, 37, 71, 73, 79, 97, 107, 113, 149, 157, 167, 179, 199
 *
 * Distinctive decompiler idioms:
 *   1. `reverse_digits(n)` — divide-by-10 digit reversal loop
 *   2. `is_prime(n) && is_prime(reverse_digits(n)) && reverse != n` — emirp test
 *   3. Count emirps <= 100 vs. emit total sum
 *
 * Results:
 *   n_tests  = 15                         = 0x0F
 *   metric_a = sum(15 emirps) % 251       = 1489 % 251 = 234 = 0xEA
 *   metric_b = count(emirp <= 100)        = 8          = 0x08
 *
 * g_result = (15<<16)|(234<<8)|8 = 0x000FEA08
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

static uint32_t reverse_digits(uint32_t n)
{
    uint32_t rev = 0u;
    while (n > 0u) {
        rev = rev * 10u + (n % 10u);
        n /= 10u;
    }
    return rev;
}

static uint32_t is_emirp(uint32_t n)
{
    if (!is_prime(n)) return 0u;
    uint32_t rev = reverse_digits(n);
    if (rev == n) return 0u;         /* palindrome primes excluded */
    return is_prime(rev);
}

void test_emirp_primes(void)
{
    uint32_t count    = 0u;
    uint32_t total_sum = 0u;
    uint32_t cnt_le100 = 0u;
    uint32_t n;

    for (n = 2u; count < 15u; n++) {
        if (is_emirp(n)) {
            total_sum += n;
            if (n <= 100u)
                cnt_le100++;
            count++;
        }
    }
    /* count=15, total_sum=1489, total_sum%251=234, cnt_le100=8 */
    g_result = (15u << 16)
             | ((total_sum % 251u) << 8)
             | (cnt_le100 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_emirp_primes();
    for (;;);
}
