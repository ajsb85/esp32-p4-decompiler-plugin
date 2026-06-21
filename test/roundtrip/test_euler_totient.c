/* test_euler_totient.c
 * Purpose   : Validate Euler's totient function via multiplicative sieve
 * Algorithm : Initialize phi[i]=i, then for each prime p (detected when
 *             phi[p]==p during iteration), subtract phi[j]/p for all multiples
 *             j of p.  Implements phi[n] = n * prod(1 - 1/p) over prime p|n.
 * Input     : limit = 30  (compute phi[1..30])
 * Metrics   : n_primes = 10 (primes in [2,30]: 2,3,5,7,11,13,17,19,23,29)
 *             sum_phi_primes = sum of phi[p] for prime p <= 30
 *                           = 1+2+4+6+10+12+16+18+22+28 = 119 = 0x77
 *             max_phi = phi[29] = 28 = 0x1C
 * g_result  = (n_primes << 16) | (sum_phi_primes << 8) | max_phi
 *           = (10 << 16) | (119 << 8) | 28 = 0x0A771C
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define ET_LIMIT 30
static int et_phi[ET_LIMIT + 1];

static void et_sieve(void) {
    for (int i = 0; i <= ET_LIMIT; i++) et_phi[i] = i;
    for (int i = 2; i <= ET_LIMIT; i++) {
        if (et_phi[i] == i) {           /* i is prime: phi unchanged so far */
            for (int j = i; j <= ET_LIMIT; j += i) {
                et_phi[j] -= et_phi[j] / i;
            }
        }
    }
}

void _start(void) {
    et_sieve();

    int n_primes = 0, sum_phi_p = 0, max_phi = 0;
    for (int i = 2; i <= ET_LIMIT; i++) {
        if (et_phi[i] == i - 1) {       /* prime iff phi[p] == p-1 */
            n_primes++;
            sum_phi_p += et_phi[i];
        }
        if (et_phi[i] > max_phi) max_phi = et_phi[i];
    }

    g_result = ((uint32_t)n_primes << 16) | ((uint32_t)sum_phi_p << 8) | (uint32_t)max_phi;
    while (1) {}
}
