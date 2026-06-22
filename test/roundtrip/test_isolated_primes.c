/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Isolated Primes fixture.
 *
 * An isolated prime (also called non-twin prime) is a prime p such that
 * neither p-2 nor p+2 is prime — i.e. p has no twin prime partner.
 *
 * First 10 isolated primes up to 100:
 *   2, 23, 37, 47, 53, 67, 79, 83, 89, 97
 *
 * Distinctive decompiler idioms:
 *   1. Test is_prime(p-2) && is_prime(p+2) as exclusion condition
 *   2. Two neighbour primality checks for each candidate
 *   3. Collect and accumulate with modular reduction
 *
 * Results:
 *   n_tests  = 10                                       = 0x0A
 *   metric_a = sum(10 isolated primes) % 251            = 577 % 251 = 75 = 0x4B
 *   metric_b = count(p % 4 == 1, p in first 10)        = 4          = 0x04
 *
 * g_result = (10<<16)|(75<<8)|4 = 0x000A4B04
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SIEVE_LIMIT 256u

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

static uint32_t is_prime_small(uint32_t n)
{
    if (n < SIEVE_LIMIT) return (sieve[n] == 0u) ? 1u : 0u;
    return 0u;
}

void test_isolated_primes(void)
{
    build_sieve();

    uint32_t count   = 0u;
    uint32_t iso_sum = 0u;
    uint32_t cnt_mod4 = 0u;
    uint32_t i;

    for (i = 2u; i < SIEVE_LIMIT && count < 10u; i++) {
        if (sieve[i] == 0u) {
            /* Isolated prime: neither neighbour at distance 2 is prime */
            uint32_t prev_twin = (i >= 2u) ? is_prime_small(i - 2u) : 0u;
            uint32_t next_twin = is_prime_small(i + 2u);
            if (prev_twin == 0u && next_twin == 0u) {
                iso_sum += i;
                if ((i % 4u) == 1u)
                    cnt_mod4++;
                count++;
            }
        }
    }

    /* count=10=0x0A, iso_sum%251=75=0x4B, cnt_mod4=4=0x04 */
    g_result = (10u << 16)
             | ((iso_sum % 251u) << 8)
             | (cnt_mod4 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_isolated_primes();
    for (;;);
}
