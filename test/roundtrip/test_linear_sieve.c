/* test_linear_sieve.c
 * Purpose   : Validate linear (Euler's) sieve for prime factorization
 * Algorithm : Each composite is crossed off exactly once by its smallest
 *             prime factor.  Builds spf[] (smallest prime factor) array
 *             in O(N) time.
 * Input     : N = 30 (sieve primes up to 29)
 * Expected  : primes ≤ 29: {2,3,5,7,11,13,17,19,23,29} → 10 primes
 *             spf[12] = 2, spf[15] = 3
 *             n_primes = 10, spf12 = 2, spf15 = 3
 * g_result  = (n_primes << 16) | (spf12 << 8) | spf15
 *           = (10 << 16) | (2 << 8) | 3 = 0x0A0203
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define LS_N 30

static int ls_spf[LS_N + 1];   /* smallest prime factor */
static int ls_primes[LS_N];
static int ls_pcnt;

static void linear_sieve(void) {
    for (int i = 2; i <= LS_N; i++) ls_spf[i] = 0;
    ls_pcnt = 0;

    for (int i = 2; i <= LS_N; i++) {
        if (ls_spf[i] == 0) {          /* i is prime */
            ls_spf[i] = i;
            ls_primes[ls_pcnt++] = i;
        }
        for (int j = 0; j < ls_pcnt; j++) {
            int p = ls_primes[j];
            if ((long)i * p > LS_N) break;
            ls_spf[i * p] = p;
            if (ls_spf[i] == p) break; /* each composite marked once */
        }
    }
}

void _start(void) {
    linear_sieve();

    int n_primes = ls_pcnt;
    int spf12    = ls_spf[12];  /* = 2 */
    int spf15    = ls_spf[15];  /* = 3 */

    g_result = ((uint32_t)n_primes << 16)
             | ((uint32_t)spf12    << 8)
             | (uint32_t)spf15;
    while (1) {}
}
