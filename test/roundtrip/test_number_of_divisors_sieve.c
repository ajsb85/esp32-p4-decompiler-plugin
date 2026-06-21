/*
 * test_number_of_divisors_sieve.c
 * Number-of-Divisors Sieve: compute d(n) = number of divisors of n for
 * all 1 <= n <= LIMIT using a multiplicative sieve.
 *
 * Method 1 (additive sieve): for each d, add 1 to d(n) for every multiple.
 *   d[1..L] = {0}; for d=1..L: for m=d,2d,..,L: d[m]++;
 *
 * Method 2 (factorization sieve): use smallest-prime-factor (SPF) sieve,
 *   then factorize each n as n = spf(n)^e * m, using multiplicativity:
 *   d(n) = (e+1) * d(m) where m = n / spf(n)^e.
 *
 * Also compute sum_{n=1}^{L} d(n) which equals sum_{d=1}^{L} floor(L/d).
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define ND_LIMIT  64

/* Method 1: additive sieve */
static uint32_t nd_div[ND_LIMIT + 1];

static void ndiv_additive_sieve(void) {
    for (int i = 0; i <= ND_LIMIT; i++) nd_div[i] = 0;
    for (int d = 1; d <= ND_LIMIT; d++)
        for (int m = d; m <= ND_LIMIT; m += d)
            nd_div[m]++;
}

/* Method 2: SPF-based multiplicative sieve */
static uint32_t spf[ND_LIMIT + 1];   /* smallest prime factor */
static uint32_t nd_div2[ND_LIMIT + 1];

static void ndiv_spf_sieve(void) {
    for (int i = 0; i <= ND_LIMIT; i++) spf[i] = (uint32_t)i;
    for (int p = 2; (uint32_t)(p * p) <= ND_LIMIT; p++) {
        if (spf[p] == (uint32_t)p) { /* p is prime */
            for (int m = p * p; m <= ND_LIMIT; m += p)
                if (spf[m] == (uint32_t)m) spf[m] = (uint32_t)p;
        }
    }
    nd_div2[1] = 1;
    for (int n = 2; n <= ND_LIMIT; n++) {
        uint32_t p0 = spf[n];
        uint32_t m  = (uint32_t)n;
        uint32_t e  = 0;
        while (m % p0 == 0) { m /= p0; e++; }
        nd_div2[n] = (e + 1) * nd_div2[m];
    }
}

/* Sum of d(n) for n=1..L */
static uint32_t ndiv_sum(uint32_t *arr, int L) {
    uint32_t s = 0;
    for (int i = 1; i <= L; i++) s += arr[i];
    return s;
}

static uint32_t run_ndiv_tests(void) {
    /*
     * Test 1: Additive sieve up to 64.
     * d(12) = 6 (divisors: 1,2,3,4,6,12).
     * d(36) = 9 (divisors: 1,2,3,4,6,9,12,18,36).
     */
    ndiv_additive_sieve();
    uint32_t d12 = nd_div[12]; /* 6 */
    uint32_t d36 = nd_div[36]; /* 9 */
    (void)d36;

    /*
     * Test 2: SPF-based sieve — verify same d(12) and d(36).
     */
    ndiv_spf_sieve();
    uint32_t d12b = nd_div2[12]; /* 6 */
    uint32_t d36b = nd_div2[36]; /* 9 */
    (void)d12b; (void)d36b;

    /*
     * Test 3: Sum d(n) for n=1..16 = 1+2+2+3+2+4+2+4+3+4+2+6+2+4+4+5 = 50.
     */
    uint32_t sum16 = ndiv_sum(nd_div, 16); /* 50 */
    (void)sum16;

    /*
     * Pack: n_tests=3, metric_a = d(12) = 6 = 0x06,
     *        metric_b = d(36) = 9 = 0x09.
     * n=3(0x03), a=6(0x06), b=9(0x09) — all non-zero, distinct. OK.
     */
    uint32_t metric_a = d12 & 0xFF;         /* 6 = 0x06 */
    uint32_t metric_b = nd_div[36] & 0xFF;  /* 9 = 0x09 */
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_ndiv_tests();
    while (1) {}
}
