/*
 * test_totient_sum.c
 * Euler's Totient Sum: compute Phi(n) = sum_{k=1}^{n} phi(k) using a
 * linear sieve that computes phi(k) for all k simultaneously.
 *
 * Algorithm:
 *   - Linear sieve: maintain smallest_prime[i].
 *   - For each composite i=p*j: if p|j, phi[i]=phi[j]*p; else phi[i]=phi[j]*(p-1).
 *   - Prefix sum gives Phi(n).
 *
 * Identity: Phi(n) = n*(n+1)/2 - sum of corrections (via Mobius inversion).
 * Simpler check: sum_{k=1}^{n} phi(k) = (1 + sum_{k=2}^{n} phi(k)).
 *
 * Tests:
 *   1. Phi(10) = phi(1)+...+phi(10) = 1+1+2+2+4+2+6+4+6+4 = 32.
 *   2. Phi(1)=1, Phi(2)=2.
 *   3. phi(12)=4 (direct from sieve).
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TOT_MAX 64u

static uint32_t tot_phi[TOT_MAX];
static uint32_t tot_primes[TOT_MAX];
static uint32_t tot_pcnt;
static uint8_t  tot_is_composite[TOT_MAX];

static void totient_sieve(void) {
    tot_phi[1u] = 1u;
    tot_pcnt    = 0u;
    for (uint32_t i = 2u; i < TOT_MAX; i++) {
        if (!tot_is_composite[i]) {
            /* i is prime */
            tot_primes[tot_pcnt++] = i;
            tot_phi[i] = i - 1u;
        }
        for (uint32_t j = 0u; j < tot_pcnt && i * tot_primes[j] < TOT_MAX; j++) {
            uint32_t p = tot_primes[j];
            tot_is_composite[i * p] = 1u;
            if (i % p == 0u) {
                tot_phi[i * p] = tot_phi[i] * p;
                break;
            } else {
                tot_phi[i * p] = tot_phi[i] * (p - 1u);
            }
        }
    }
}

/* Sum phi(1) + phi(2) + ... + phi(n) */
static uint32_t totient_sum(uint32_t n) {
    uint32_t s = 0u;
    for (uint32_t k = 1u; k <= n && k < TOT_MAX; k++) {
        s += tot_phi[k];
    }
    return s;
}

static uint32_t run_totient_tests(void) {
    uint32_t n_tests = 0u;

    totient_sieve();

    /*
     * Test 1: totient_sum(10).
     * phi: 1,1,2,2,4,2,6,4,6,4 => sum=32.
     */
    uint32_t s10 = totient_sum(10u);
    n_tests++;
    /* s10 == 32 = 0x20 */

    /*
     * Test 2: totient_sum(2) = phi(1)+phi(2) = 1+1 = 2.
     */
    uint32_t s2 = totient_sum(2u);
    n_tests++;
    /* s2 == 2 */

    /*
     * Test 3: phi(12) directly.
     * phi(12)=phi(4*3)=phi(4)*phi(3)*(stuff) = 4 (12*(1-1/2)*(1-1/3)=4).
     * From sieve: phi[12]=4.
     */
    uint32_t phi12 = tot_phi[12u];
    n_tests++;
    /* phi12 == 4 */

    /*
     * Pack result:
     *   n_tests=3=0x03
     *   metric_a = s10 & 0xFFu = 32 = 0x20
     *   metric_b = (s2 << 4) | phi12 = (2<<4)|4 = 36 = 0x24
     *   Bytes: 0x03, 0x20, 0x24 — 0x20 and 0x24 are distinct, 0x03 distinct. Non-zero. Good.
     *   Wait: 0x20 != 0x24, all non-zero. Fine.
     */
    uint32_t metric_a = s10 & 0xFFu;
    uint32_t metric_b = (s2 << 4u) | phi12;
    return (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    g_result = run_totient_tests();
    while (1) {}
}
