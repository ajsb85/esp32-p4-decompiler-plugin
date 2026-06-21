/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Sieve of Eratosthenes round-trip fixture.
 *
 * Generates all primes up to SIEVE_LIMIT using the classic sieve algorithm.
 * The outer loop iterates i from 2 to sqrt(SIEVE_LIMIT); for each prime i,
 * the inner loop marks multiples starting at i*i (the key decompiler idiom).
 *
 * SIEVE_LIMIT = 50
 *
 * Primes ≤ 50:
 *   2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47
 *   n_primes  = 15
 *   last_prime = 47 = 0x2F
 *   xor_primes = 2^3^5^7^11^13^17^19^23^29^31^37^41^43^47 = 26 = 0x1A
 *
 * g_result = (n_primes << 16) | (last_prime << 8) | xor_primes = 0x000F2F1A
 *
 * Recognizable decompiler idioms:
 *   sieve[0] = sieve[1] = 0;         ← exclude 0 and 1
 *   for (i=2; i*i<=N; i++) if (sieve[i]) for (j=i*i; j<=N; j+=i) sieve[j]=0;
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Sieve ────────────────────────────────────────────────────────────────── */

#define SIEVE_LIMIT 50

static int sieve[SIEVE_LIMIT + 1];

static void eratosthenes(void)
{
    for (int i = 0; i <= SIEVE_LIMIT; i++)
        sieve[i] = 1;
    sieve[0] = 0;
    sieve[1] = 0;

    for (int i = 2; i * i <= SIEVE_LIMIT; i++) {
        if (sieve[i]) {
            for (int j = i * i; j <= SIEVE_LIMIT; j += i)
                sieve[j] = 0;
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_sieve(void)
{
    eratosthenes();

    int n_primes = 0, last_prime = 0;
    uint32_t xor_p = 0;
    for (int i = 2; i <= SIEVE_LIMIT; i++) {
        if (sieve[i]) {
            n_primes++;
            last_prime = i;
            xor_p ^= (uint32_t)i;
        }
    }

    g_result = ((uint32_t)n_primes << 16)
             | ((uint32_t)last_prime << 8)
             | (xor_p & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_sieve();
    for (;;);
}
