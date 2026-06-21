/* test_powerful_numbers.c — Powerful numbers (32-bit, no libc)
 *
 * A positive integer n is "powerful" if for every prime p dividing n,
 * p^2 also divides n.  Equivalently: in the prime factorisation of n,
 * every prime appears with exponent >= 2.
 *
 * Examples: 1, 4, 8, 9, 16, 25, 27, 32, 36, 49, 64, 72, 100, ...
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Check whether n is powerful.
 * Trial-divide by all primes up to sqrt(n); each time a prime divides n,
 * it must divide with multiplicity >= 2. */
static uint32_t is_powerful(uint32_t n) {
    if (n == 0) return 0;
    if (n == 1) return 1;

    uint32_t d;
    for (d = 2; d * d <= n; d++) {
        if (n % d == 0) {
            /* d divides n — check multiplicity >= 2 */
            if ((n / d) % d != 0) return 0;  /* only once → not powerful */
            /* consume all factors of d */
            while (n % d == 0) n /= d;
        }
    }
    /* If n > 1 here, it's a prime factor with exponent 1 → not powerful */
    if (n > 1) return 0;
    return 1;
}

/* Collect powerful numbers up to limit into out[], return count. */
static uint32_t collect_powerful(uint32_t limit, uint32_t *out, uint32_t maxout) {
    uint32_t cnt = 0;
    uint32_t n;
    for (n = 1; n <= limit && cnt < maxout; n++) {
        if (is_powerful(n)) {
            out[cnt++] = n;
        }
    }
    return cnt;
}

static void test_powerful_numbers(void) {
    /* Known powerful numbers up to 200:
     * 1,4,8,9,16,25,27,32,36,49,64,72,100,108,121,125,128,144,169,196,200
     * = 21 values */
    uint32_t buf[64];
    uint32_t cnt = collect_powerful(200, buf, 64);

    /* n_tests = cnt (should be 21 = 0x15) */
    uint32_t n_tests = cnt;   /* 21 */

    /* metric_a = count of powerful numbers that are perfect squares (<= 200)
     * Perfect squares that are powerful: 1,4,9,16,25,36,49,64,100,121,144,169,196 = 13 = 0x0D */
    uint32_t sq_count = 0;
    uint32_t i;
    for (i = 0; i < cnt; i++) {
        uint32_t v = buf[i];
        uint32_t r = 1;
        while (r * r < v) r++;
        if (r * r == v) sq_count++;
    }
    uint32_t metric_a = sq_count & 0xFFu;  /* 13 = 0x0D */

    /* metric_b = sum of buf[0..3] mod 251 (first 4 powerful: 1+4+8+9=22=0x16) */
    uint32_t small_sum = 0;
    uint32_t lim = cnt < 4 ? cnt : 4;
    for (i = 0; i < lim; i++) small_sum += buf[i];
    uint32_t metric_b = small_sum % 251u;  /* 22 = 0x16 */

    /* g_result = (0x15 << 16) | (0x0D << 8) | 0x16 = 0x150D16 all non-zero & distinct ✓ */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    test_powerful_numbers();
    while (1) {}
}
