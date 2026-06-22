/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Prime Triplets fixture.
 *
 * A prime triplet of type (p, p+2, p+6): three primes p, p+2, p+6.
 * (The only allowed pattern for 3 primes in 6 consecutive integers,
 * aside from (2,3,5) and (3,5,7).)
 *
 * Type-1 triplets with p <= 400:
 *   (5,7,11), (11,13,17), (17,19,23), (41,43,47), (101,103,107),
 *   (107,109,113), (191,193,197), (227,229,233), (311,313,317), (347,349,353)
 *
 * Distinctive decompiler idioms:
 *   1. Sieve then test p, p+2, p+6 simultaneously
 *   2. Count triplets with p < 200 as secondary metric
 *   3. Pack: n_tests=10, metric_a=sum(p)%251=103, metric_b=count(p<200)=7
 *
 * Results:
 *   n_tests  = 10                            = 0x0A
 *   metric_a = sum of smallest p, mod 251    = 1358 % 251 = 103 = 0x67
 *   metric_b = count(p < 200)                = 7           = 0x07
 *
 * g_result = (10<<16)|(103<<8)|7 = 0x000A6707
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SIEVE_LIMIT 408u

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

void test_prime_triplets(void)
{
    build_sieve();

    uint32_t count    = 0u;
    uint32_t sum_p    = 0u;
    uint32_t cnt_lt200 = 0u;
    uint32_t p;

    for (p = 2u; p + 6u < SIEVE_LIMIT; p++) {
        if (sieve[p] == 0u && sieve[p + 2u] == 0u && sieve[p + 6u] == 0u) {
            sum_p += p;
            if (p < 200u)
                cnt_lt200++;
            count++;
        }
    }

    /* count=10=0x0A, sum%251=103=0x67, cnt_lt200=7=0x07 */
    g_result = (10u << 16)
             | ((sum_p % 251u) << 8)
             | (cnt_lt200 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_prime_triplets();
    for (;;);
}
