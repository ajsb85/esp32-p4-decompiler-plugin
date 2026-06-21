/* test_prime_sieve_segmented.c
 * Purpose   : Validate segmented sieve of Eratosthenes for range [L, R]
 * Algorithm : Two-phase sieve:
 *             Phase 1: Simple sieve up to sqrt(R) to find base primes.
 *             Phase 2: For segment [L, R], mark composites using each base prime p:
 *                      start at ceil(L/p)*p (skip p itself if start==p).
 *             Counts primes in [100, 200] and records first/last prime.
 * Input     : L=100, R=200
 * Expected  : 21 primes in [100,200]; first=101, last=199
 *             n_primes=21 (=0x15), first%256=101 (=0x65), last%256=199 (=0xC7)
 * g_result  = (n_primes << 16) | ((first % 256) << 8) | (last % 256)
 *           = (21 << 16) | (101 << 8) | 199 = 0x1565C7
 */

#include <stdint.h>

volatile uint32_t g_result;

#define SEG_L       100
#define SEG_R       200
#define SEG_SQRT    15   /* floor(sqrt(200)) = 14, use 15 for safety */
#define SEG_LEN     (SEG_R - SEG_L + 1)

static uint8_t seg_small[SEG_SQRT + 1]; /* 1 = prime */
static uint8_t seg_sieve[SEG_LEN];      /* 1 = prime in [L,R] */
static int     seg_primes[8];           /* base primes <= sqrt(R) */
static int     seg_np;                  /* count of base primes */

static void seg_build(void) {
    /* Phase 1: sieve up to SEG_SQRT */
    for (int i = 2; i <= SEG_SQRT; i++) seg_small[i] = 1;
    for (int i = 2; i <= SEG_SQRT; i++) {
        if (!seg_small[i]) continue;
        seg_primes[seg_np++] = i;
        for (int j = i * i; j <= SEG_SQRT; j += i)
            seg_small[j] = 0;
    }

    /* Phase 2: segmented sieve for [SEG_L, SEG_R] */
    for (int i = 0; i < SEG_LEN; i++) seg_sieve[i] = 1;

    for (int pi = 0; pi < seg_np; pi++) {
        int p = seg_primes[pi];
        /* First multiple of p >= SEG_L */
        int start = ((SEG_L + p - 1) / p) * p;
        if (start == p) start += p; /* skip p itself if it falls in range */
        for (int j = start; j <= SEG_R; j += p)
            seg_sieve[j - SEG_L] = 0;
    }
}

void _start(void) {
    seg_build();

    int n_primes = 0, first_prime = 0, last_prime = 0;
    for (int i = 0; i < SEG_LEN; i++) {
        if (seg_sieve[i]) {
            n_primes++;
            if (!first_prime) first_prime = SEG_L + i;
            last_prime = SEG_L + i;
        }
    }
    /* n_primes=21 (0x15), first=101 (0x65), last=199 (0xC7) -> 0x1565C7 */
    g_result = ((uint32_t)n_primes    << 16)
             | ((uint32_t)(first_prime & 0xFF) << 8)
             | ((uint32_t)(last_prime  & 0xFF));
    while (1) {}
}
