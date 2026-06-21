/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Möbius Function via Linear Sieve fixture.
 *
 * Computes the Möbius function μ(n) for all n in [1..30] using a linear
 * (Euler) sieve that processes each composite number exactly once.
 *
 * μ(n) definition:
 *   μ(1) = 1
 *   μ(n) = 0  if n has any squared prime factor
 *   μ(n) = (-1)^k  where k is the number of distinct prime factors of n
 *
 * Sieve recurrence:
 *   p prime: μ(p) = -1
 *   p | i  (p² | ip): μ(ip) = 0
 *   p ∤ i:            μ(ip) = -μ(i)   (one more distinct prime factor)
 *
 * Distinctive decompiler idioms:
 *   1. Linear sieve: `for j; i*primes[j] <= N; j++` marks composites once
 *   2. `if (i % primes[j] == 0) { mu[x]=0; break; }` — squared factor early exit
 *   3. `mu[x] = -mu[i]` — negate parent Möbius value to toggle parity
 *   4. Signed array: `mu[i]` takes values {-1, 0, 1}
 *
 * Results over n=1..30:
 *   squarefree (|μ|=1): {1,2,3,5,6,7,10,11,13,14,15,17,19,21,22,23,26,29,30}
 *   count |μ|=1 = 19 = 0x13
 *   count μ=-1  = 11 = 0x0B  (squarefree with odd #prime factors)
 *
 * n_tests  = 1   (one sieve run)
 * sum_abs  = 19  (squarefree count)
 * cnt_neg  = 11
 *
 * g_result = (n_tests << 16) | (sum_abs << 8) | cnt_neg = 0x0001130B
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MU_N 30

static int mu[MU_N + 1];
static int primes[MU_N + 1];
static int is_composite[MU_N + 1];

void test_mobius(void)
{
    int cnt = 0;
    mu[1] = 1;

    for (int i = 2; i <= MU_N; i++) {
        if (!is_composite[i]) {
            primes[cnt++] = i;
            mu[i] = -1;  /* prime → exactly 1 prime factor */
        }
        for (int j = 0; j < cnt && i * primes[j] <= MU_N; j++) {
            int x = i * primes[j];
            is_composite[x] = 1;
            if (i % primes[j] == 0) {
                mu[x] = 0;  /* p² divides x → μ = 0 */
                break;
            } else {
                mu[x] = -mu[i];  /* one more distinct prime */
            }
        }
    }

    uint32_t sum_abs = 0, cnt_neg = 0;
    for (int i = 1; i <= MU_N; i++) {
        if (mu[i] != 0) sum_abs++;
        if (mu[i] == -1) cnt_neg++;
    }
    /* sum_abs=19, cnt_neg=11 */

    g_result = (1u << 16)
             | (sum_abs << 8)
             | (cnt_neg & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_mobius();
    for (;;);
}
