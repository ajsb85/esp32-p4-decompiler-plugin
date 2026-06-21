/* test_primes_in_arithmetic_progression.c
 * Purpose   : Find primes in an arithmetic progression a + k*d.
 * Algorithm : Enumerate the sequence a=5, d=6 for k=0..7 (8 terms):
 *               5, 11, 17, 23, 29, 35, 41, 47
 *             Test each for primality with trial division.
 *             Dirichlet's theorem: infinitely many primes exist in any AP
 *             a+kd where gcd(a,d)=1.  Here gcd(5,6)=1 so primes are dense.
 *
 * Distinctive decompiler idioms:
 *   1. AP generation: `val = ap_first + i * ap_step` in a loop
 *   2. Trial division primality: `for (j=2; j*j <= val; j++) if(val%j==0) break`
 *   3. Composite detection: 35 = 5×7 filtered out, all others prime
 *
 * Sequence: 5, 11, 17, 23, 29, [35 composite], 41, 47
 * Primes found: {5, 11, 17, 23, 29, 41, 47}
 *
 * n_terms   = 8
 * count_p   = 7  (0x07)
 * xor_p     = 5^11^17^23^29^41^47 = 27  (0x1B)
 *             Verification: 5^11=14, ^17=31, ^23=8, ^29=21, ^41=52, ^47=27
 *
 * g_result = (n_terms<<16) | (count_p<<8) | xor_p
 *          = (8<<16) | (7<<8) | 27
 *          = 0x08071B
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define AP_N     8u
#define AP_FIRST 5u
#define AP_STEP  6u

static uint32_t is_prime_trial(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if (n % 2u == 0u) return 0u;
    for (uint32_t j = 3u; j * j <= n; j += 2u) {
        if (n % j == 0u) return 0u;
    }
    return 1u;
}

void test_primes_in_arithmetic_progression(void)
{
    uint32_t count_p = 0u;
    uint32_t xor_p   = 0u;

    for (uint32_t i = 0u; i < AP_N; i++) {
        uint32_t val = AP_FIRST + i * AP_STEP;
        if (is_prime_trial(val)) {
            count_p++;
            xor_p ^= val;
        }
    }
    /* count_p=7, xor_p=27=0x1B, AP_N=8 → 0x08071B */
    g_result = (AP_N << 16) | ((count_p & 0xFFu) << 8) | (xor_p & 0xFFu);
}

void _start(void)
{
    test_primes_in_arithmetic_progression();
    while (1) {}
}
