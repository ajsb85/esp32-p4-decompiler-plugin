/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Primorial fixture.
 *
 * Primorial P(k) = product of the first k primes.
 * Computes P(1)..P(5) and accumulates sum and XOR of (P(k) mod 256).
 *
 * Distinctive decompiler idioms:
 *   1. `is_prime(n)`: trial division loop `for(i=2;i*i<=n;i++) if(n%i==0) return 0`
 *   2. collect primes lazily: `for(n=2; pc<5; n++) if(is_prime(n)) primes[pc++]=n`
 *   3. `prim = prim * primes[k]` — running product
 *   4. `sum_mod += prim & 0xFF; xor_mod ^= prim & 0xFF` — accumulate mod-256
 *
 * First 5 primes: {2,3,5,7,11}
 * Primorials:      {2, 6, 30, 210, 2310}
 * mod 256:         {2, 6, 30, 210,   6}   (2310 mod 256 = 6)
 * sum_mod = 2+6+30+210+6 = 254 = 0xFE
 * xor_mod = 2^6^30^210^6 = 206 = 0xCE
 *
 * g_result = (5<<16) | (254<<8) | 206 = 0x0005FECE
 */
#include <stdint.h>

volatile uint32_t g_result;

static int pr_is_prime(int n)
{
    if (n < 2) return 0;
    for (int i = 2; i * i <= n; i++)
        if (n % i == 0) return 0;
    return 1;
}

void test_primorial(void)
{
    int primes[5], pc = 0;
    for (int n = 2; pc < 5; n++)
        if (pr_is_prime(n)) primes[pc++] = n;

    uint32_t prim = 1, sum_mod = 0, xor_mod = 0;
    for (int k = 0; k < 5; k++) {
        prim = prim * (uint32_t)primes[k];
        sum_mod += prim & 0xFFu;
        xor_mod ^= prim & 0xFFu;
    }
    /* sum_mod=254, xor_mod=206 */
    g_result = (5u << 16) | ((sum_mod & 0xFFu) << 8) | (xor_mod & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_primorial();
    for (;;);
}
