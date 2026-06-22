/* test_zeisel_numbers.c
 * Purpose   : Find Zeisel numbers in range 2..500
 * Algorithm : A Zeisel number is a composite with at least 3 distinct prime
 *             factors p1 < p2 < p3 ... that satisfy a linear recurrence
 *             p_i = a*p_{i-1} + b (same a >= 1, b >= 1 for all consecutive pairs).
 *             For each candidate n: factorize, extract sorted distinct primes,
 *             check if they form an arithmetic-progression-like linear recurrence.
 * Input     : range 2..500 (n_tests = 499)
 * Expected  : Zeisel numbers in 2..500: 105,110,220,231,238,315,440,476
 *             count = 8
 *             sum   = 105+110+220+231+238+315+440+476 = 2135
 *             metric_a = count & 0xFF = 8
 *             metric_b = sum % 251 = 127 (2135 = 8*251 + 127)
 *             n_tests  = 499
 * g_result  = (499<<16)|(8<<8)|127 = 0x1F3087F
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* Return smallest prime factor of n (n > 1), or 0 if n==1 */
static uint32_t spf(uint32_t n) {
    if (n < 2u) return 0u;
    if (n % 2u == 0u) return 2u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return d;
    }
    return n;
}

/* Extract distinct prime factors of n into pf[], return count (max 8) */
static uint32_t distinct_primes(uint32_t n, uint32_t pf[], uint32_t maxpf) {
    uint32_t cnt = 0u;
    uint32_t last = 0u;
    while (n > 1u && cnt < maxpf) {
        uint32_t p = spf(n);
        if (p != last) {
            pf[cnt++] = p;
            last = p;
        }
        while (n % p == 0u) n /= p;
    }
    return cnt;
}

static uint32_t is_zeisel(uint32_t n) {
    if (n < 3u) return 0u;
    uint32_t pf[8];
    uint32_t cnt = distinct_primes(n, pf, 8u);
    if (cnt < 3u) return 0u;
    /* Compute a and b from first two factors */
    uint32_t d0 = pf[1] - pf[0];
    uint32_t d1 = pf[2] - pf[1];
    /* a = (pf[2]-pf[1]) / (pf[1]-pf[0]) must be integer */
    if (d0 == 0u || d1 % d0 != 0u) return 0u;
    uint32_t a = d1 / d0;
    if (a < 1u) return 0u;
    /* b = pf[1] - a*pf[0], must be >= 1 */
    uint32_t apf0 = a * pf[0];
    if (pf[1] <= apf0) return 0u;
    uint32_t b = pf[1] - apf0;
    if (b < 1u) return 0u;
    /* Verify all subsequent factors */
    for (uint32_t i = 2u; i < cnt; i++) {
        if (pf[i] != a * pf[i-1u] + b) return 0u;
    }
    return 1u;
}

void _start(void) {
    uint32_t n_tests = 499u;
    uint32_t count   = 0u;
    uint32_t zsum    = 0u;

    for (uint32_t n = 2u; n <= n_tests + 1u; n++) {
        if (is_zeisel(n)) {
            count++;
            zsum += n;
        }
    }

    /* n_tests=499, count=8, zsum%251=127 => 0x1F3087F */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = zsum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
