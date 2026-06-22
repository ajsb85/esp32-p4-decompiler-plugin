/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Weak Primes fixture.
 *
 * A weak prime is a prime p(n) such that p(n) < (p(n-1) + p(n+1)) / 2,
 * i.e. p(n) is less than the arithmetic mean of its immediate prime neighbours.
 * Equivalently: p(n-1) + p(n+1) > 2 * p(n).
 *
 * First 15 weak primes:
 *   3, 7, 13, 19, 23, 31, 43, 47, 61, 73, 83, 89, 103, 109, 113
 *
 * Distinctive decompiler idioms:
 *   1. Arithmetic-mean neighbour test: p_prev + p_next > 2*p_mid
 *   2. Rolling three-element prime window (p_prev, p_mid, p_next)
 *   3. Running sum with modular reduction
 *
 * Results:
 *   n_tests  = 15                                    = 0x0F
 *   metric_a = sum(first 15 weak primes) % 251       = 817 % 251 = 64 = 0x40
 *   metric_b = count(p % 6 == 1, p in first 15)      = 9           = 0x09
 *
 * g_result = (15<<16)|(64<<8)|9 = 0x000F4009
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

void test_weak_primes(void)
{
    build_sieve();

    uint32_t primes[100];
    uint32_t np = 0u;
    uint32_t i;
    for (i = 2u; i < SIEVE_LIMIT && np < 100u; i++) {
        if (sieve[i] == 0u)
            primes[np++] = i;
    }

    uint32_t count    = 0u;
    uint32_t weak_sum = 0u;
    uint32_t cnt_mod6 = 0u;

    for (i = 1u; i < np - 1u && count < 15u; i++) {
        uint32_t p_prev = primes[i - 1u];
        uint32_t p_mid  = primes[i];
        uint32_t p_next = primes[i + 1u];
        /* Weak prime: p_mid < arithmetic mean of neighbours */
        if (p_prev + p_next > 2u * p_mid) {
            weak_sum += p_mid;
            if ((p_mid % 6u) == 1u)
                cnt_mod6++;
            count++;
        }
    }

    /* count=15=0x0F, weak_sum%251=64=0x40, cnt_mod6=9=0x09 */
    g_result = (15u << 16)
             | ((weak_sum % 251u) << 8)
             | (cnt_mod6 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_weak_primes();
    for (;;);
}
