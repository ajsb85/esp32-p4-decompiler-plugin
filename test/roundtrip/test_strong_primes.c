/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Strong Primes fixture.
 *
 * A strong prime is a prime p(n) that is greater than the arithmetic
 * mean of its immediate prime neighbours:
 *   p(n) > (p(n-1) + p(n+1)) / 2
 * equivalently: 2*p(n) > p(n-1) + p(n+1)
 *
 * First 15 strong primes:
 *   11, 17, 29, 37, 41, 59, 67, 71, 79, 97, 101, 107, 127, 137, 149
 *
 * Distinctive decompiler idioms:
 *   1. Generate a sieve of primes, then walk consecutive triples
 *   2. Condition `2*p_mid > p_prev + p_next` — strong prime test
 *   3. Dual metrics: sum mod 251, and count <= 50
 *
 * Results:
 *   n_tests  = 15                           = 0x0F
 *   metric_a = sum(15 strong primes) % 251  = 1129 % 251 = 125 = 0x7D
 *   metric_b = count(strong prime <= 50)    = 5           = 0x05
 *
 * g_result = (15<<16)|(125<<8)|5 = 0x000F7D05
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SIEVE_LIMIT 512u

static uint8_t sieve[SIEVE_LIMIT];   /* 0 = prime candidate, 1 = composite */

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

void test_strong_primes(void)
{
    build_sieve();

    /* Collect primes into compact array */
    uint32_t primes[100];
    uint32_t np = 0u;
    uint32_t i;
    for (i = 2u; i < SIEVE_LIMIT && np < 100u; i++) {
        if (sieve[i] == 0u)
            primes[np++] = i;
    }

    uint32_t count    = 0u;
    uint32_t total_sum = 0u;
    uint32_t cnt_le50  = 0u;

    /* Walk triples to find strong primes */
    for (i = 1u; i < np - 1u && count < 15u; i++) {
        uint32_t p_prev = primes[i - 1u];
        uint32_t p_mid  = primes[i];
        uint32_t p_next = primes[i + 1u];
        if (2u * p_mid > p_prev + p_next) {
            total_sum += p_mid;
            if (p_mid <= 50u)
                cnt_le50++;
            count++;
        }
    }
    /* count=15, total_sum=1129, total_sum%251=125, cnt_le50=5 */
    g_result = (15u << 16)
             | ((total_sum % 251u) << 8)
             | (cnt_le50 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_strong_primes();
    for (;;);
}
