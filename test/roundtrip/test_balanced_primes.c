/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Balanced Primes fixture.
 *
 * A balanced prime is a prime p(n) that equals the arithmetic mean of its
 * immediate prime neighbours: 2*p(n) == p(n-1) + p(n+1).
 *
 * Balanced primes up to 600:
 *   5, 53, 157, 173, 211, 257, 263, 373, 563, 593
 *
 * Distinctive decompiler idioms:
 *   1. Collect prime array, then walk consecutive triples
 *   2. Condition: 2*p_mid == p_prev + p_next  (exact equality, not inequality)
 *   3. Dual metrics: sum mod 251, count with p <= 200
 *
 * Results:
 *   n_tests  = 10                                = 0x0A
 *   metric_a = sum(balanced primes) % 251        = 2648 % 251 = 138 = 0x8A
 *   metric_b = count(balanced prime <= 200)      = 4           = 0x04
 *
 * g_result = (10<<16)|(138<<8)|4 = 0x000A8A04
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SIEVE_LIMIT 600u

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

void test_balanced_primes(void)
{
    build_sieve();

    uint32_t primes[120];
    uint32_t np = 0u;
    uint32_t i;
    for (i = 2u; i < SIEVE_LIMIT && np < 120u; i++) {
        if (sieve[i] == 0u)
            primes[np++] = i;
    }

    uint32_t count   = 0u;
    uint32_t bal_sum = 0u;
    uint32_t cnt_le200 = 0u;

    for (i = 1u; i < np - 1u; i++) {
        uint32_t p_prev = primes[i - 1u];
        uint32_t p_mid  = primes[i];
        uint32_t p_next = primes[i + 1u];
        if (2u * p_mid == p_prev + p_next) {
            bal_sum += p_mid;
            if (p_mid <= 200u)
                cnt_le200++;
            count++;
        }
    }

    /* count=10=0x0A, bal_sum%251=138=0x8A, cnt_le200=4=0x04 */
    g_result = (10u << 16)
             | ((bal_sum % 251u) << 8)
             | (cnt_le200 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_balanced_primes();
    for (;;);
}
