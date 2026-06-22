/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Good Primes fixture.
 *
 * A good prime is a prime p(n) such that p(n)^2 > p(n-1)*p(n+1),
 * i.e. the geometric mean of its neighbours is less than p(n) itself.
 *
 * First 15 good primes:
 *   5, 11, 17, 29, 37, 41, 53, 59, 67, 71, 79, 97, 101, 107, 127
 *
 * Distinctive decompiler idioms:
 *   1. Squaring the middle prime: p_mid * p_mid
 *   2. Product of neighbours: p_prev * p_next
 *   3. Condition: p_mid^2 > p_prev * p_next (geometric-mean test)
 *
 * Results:
 *   n_tests  = 15                              = 0x0F
 *   metric_a = sum(15 good primes) % 251       = 901 % 251 = 148 = 0x94
 *   metric_b = count(good prime <= 50)         = 6          = 0x06
 *
 * g_result = (15<<16)|(148<<8)|6 = 0x000F9406
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

void test_good_primes(void)
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
    uint32_t good_sum = 0u;
    uint32_t cnt_le50  = 0u;

    for (i = 1u; i < np - 1u && count < 15u; i++) {
        uint32_t p_prev = primes[i - 1u];
        uint32_t p_mid  = primes[i];
        uint32_t p_next = primes[i + 1u];
        /* Good prime test: p_mid^2 > p_prev * p_next */
        if (p_mid * p_mid > p_prev * p_next) {
            good_sum += p_mid;
            if (p_mid <= 50u)
                cnt_le50++;
            count++;
        }
    }

    /* count=15=0x0F, good_sum%251=148=0x94, cnt_le50=6=0x06 */
    g_result = (15u << 16)
             | ((good_sum % 251u) << 8)
             | (cnt_le50 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_good_primes();
    for (;;);
}
