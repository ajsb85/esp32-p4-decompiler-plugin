/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Palindromic Primes fixture.
 *
 * A palindromic prime is a prime number that is also a palindrome
 * in base 10 (reads the same forwards and backwards).
 *
 * First 12 palindromic primes:
 *   2, 3, 5, 7, 11, 101, 131, 151, 181, 191, 313, 353
 *
 * Distinctive decompiler idioms:
 *   1. Digit reversal loop: extract digits and rebuild reversed number
 *   2. Palindrome test: reversed == original
 *   3. Combined sieve + palindrome filter
 *
 * Results:
 *   n_tests  = 12                                  = 0x0C
 *   metric_a = sum(first 12 pal primes) % 251      = 1449 % 251 = 194 = 0xC2
 *   metric_b = count(p < 200, p in first 12)       = 10         = 0x0A
 *
 * g_result = (12<<16)|(194<<8)|10 = 0x000CC20A
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SIEVE_LIMIT 512u

static uint8_t sieve[SIEVE_LIMIT];

static void build_sieve(void)
{
    uint32_t i, j;
    sieve[0] = 1u; sieve[1] = 1u;
    for (i = 2u; i < SIEVE_LIMIT; i++) {
        if (sieve[i] == 0u) {
            for (j = i * i; j < SIEVE_LIMIT; j += i)
                sieve[j] = 1u;
        }
    }
}

static uint32_t is_palindrome(uint32_t n)
{
    uint32_t original = n;
    uint32_t reversed = 0u;
    while (n > 0u) {
        reversed = reversed * 10u + (n % 10u);
        n /= 10u;
    }
    return (reversed == original) ? 1u : 0u;
}

void test_palindromic_primes(void)
{
    build_sieve();

    uint32_t count   = 0u;
    uint32_t pal_sum = 0u;
    uint32_t cnt_lt200 = 0u;
    uint32_t i;

    for (i = 2u; i < SIEVE_LIMIT && count < 12u; i++) {
        if (sieve[i] == 0u && is_palindrome(i)) {
            pal_sum += i;
            if (i < 200u)
                cnt_lt200++;
            count++;
        }
    }

    /* count=12=0x0C, pal_sum%251=194=0xC2, cnt_lt200=10=0x0A */
    g_result = (12u << 16)
             | ((pal_sum % 251u) << 8)
             | (cnt_lt200 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_palindromic_primes();
    for (;;);
}
