/* test_semiprime_factor.c — Semiprime detection and factoring (32-bit, no libc)
 *
 * A semiprime is a natural number that is the product of exactly two primes
 * (not necessarily distinct).  Examples: 4=2*2, 6=2*3, 9=3*3, 10=2*5, 14=2*7, ...
 *
 * We detect semiprimes and find their two prime factors by trial division.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Smallest prime factor of n (returns n itself if n is prime, 1 if n<=1). */
static uint32_t spf(uint32_t n) {
    if (n <= 1) return 1;
    if ((n & 1u) == 0) return 2;
    uint32_t d;
    for (d = 3; d * d <= n; d += 2) {
        if (n % d == 0) return d;
    }
    return n; /* n is prime */
}

/* Is n prime? */
static uint32_t is_prime(uint32_t n) {
    if (n < 2) return 0;
    return spf(n) == n;
}

/* Is n a semiprime?  If yes, write the two prime factors into p1,p2. */
static uint32_t is_semiprime(uint32_t n, uint32_t *p1, uint32_t *p2) {
    if (n < 4) return 0;
    uint32_t f = spf(n);
    uint32_t q = n / f;
    if (is_prime(q)) {
        *p1 = f;
        *p2 = q;
        return 1;
    }
    return 0;
}

static void test_semiprime_factor(void) {
    /* Collect semiprimes in [4..100] */
    uint32_t sp_cnt = 0;
    uint32_t factor_sum = 0;  /* sum of smaller prime factors */
    uint32_t sq_count = 0;    /* semiprimes that are perfect squares: 4,9,25,49 */

    uint32_t n;
    for (n = 4; n <= 100; n++) {
        uint32_t p1 = 0, p2 = 0;
        if (is_semiprime(n, &p1, &p2)) {
            sp_cnt++;
            factor_sum += p1;  /* p1 <= p2 since spf returns smallest */
            /* Perfect square semiprime: p1 == p2 */
            if (p1 == p2) sq_count++;
        }
    }

    /* Known semiprimes in [4..100]:
     * 4,6,9,10,14,15,21,22,25,26,33,34,35,38,39,46,49,51,55,57,58,
     * 62,65,69,74,77,82,85,86,87,91,93,94,95
     * = 34 values  → n_tests = 34 = 0x22
     *
     * sq_count: 4(=2*2), 9(=3*3), 25(=5*5), 49(=7*7) → 4 = 0x04
     *
     * factor_sum: sum of smallest prime factors of each:
     * 4→2, 6→2, 9→3, 10→2, 14→2, 15→3, 21→3, 22→2, 25→5, 26→2,
     * 33→3, 34→2, 35→5, 38→2, 39→3, 46→2, 49→7, 51→3, 55→5, 57→3,
     * 58→2, 62→2, 65→5, 69→3, 74→2, 77→7, 82→2, 85→5, 86→2, 87→3,
     * 91→7, 93→3, 94→2, 95→5
     * sum = 2+2+3+2+2+3+3+2+5+2+3+2+5+2+3+2+7+3+5+3+2+2+5+3+2+7+2+5+2+3+7+3+2+5
     *     = let's compute: (2*12)+(3*10)+(5*7)+(7*3) ...
     *       = 24+30+35+21 = 110 = 0x6E
     * metric_b = 110 & 0xFF = 0x6E
     *
     * g_result = (0x22 << 16) | (0x04 << 8) | 0x6E = 0x22046E  all non-zero & distinct ✓ */

    uint32_t n_tests = sp_cnt;
    uint32_t metric_a = sq_count & 0xFFu;
    uint32_t metric_b = factor_sum & 0xFFu;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    test_semiprime_factor();
    while (1) {}
}
