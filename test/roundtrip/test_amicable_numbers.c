/* test_amicable_numbers.c
 * Purpose   : Find amicable numbers in [200..300].
 *             Two distinct numbers m and n are amicable if sigma(m)=n and sigma(n)=m,
 *             where sigma is the proper-divisor sum.
 *             The pair (220, 284) is the smallest; both lie in [200..300].
 *
 * Algorithm : For each n in [200..300], compute s=sigma(n).
 *             If s != n and sigma(s) == n, then n is amicable.
 *
 * Distinctive decompiler idioms:
 *   1. sigma helper: `for d=1; d<n; d++` with `if n%d==0 sum+=d`
 *   2. Mutual-check: `sigma(sigma(n)) == n && sigma(n) != n`
 *   3. Accumulate count and sum_mod of amicable found
 *
 * n_tests   = 101   (range [200..300] inclusive = 101 values, 0x65)
 * am_count  = 2     (220, 284, 0x02)
 * sum_mod   = 248   ((220+284) & 0xFF = 504 & 0xFF = 0xF8)
 *
 * g_result = (n_tests<<16) | (am_count<<8) | sum_mod = 0x6502F8
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define AM_LO    200u
#define AM_HI    300u

static uint32_t am_sigma(uint32_t n)
{
    uint32_t s = 0u;
    for (uint32_t d = 1u; d < n; d++) {
        if (n % d == 0u) {
            s += d;
        }
    }
    return s;
}

void test_amicable_numbers(void)
{
    uint32_t am_count = 0u;
    uint32_t am_sum   = 0u;

    for (uint32_t n = AM_LO; n <= AM_HI; n++) {
        uint32_t s = am_sigma(n);
        if (s != n && am_sigma(s) == n) {
            am_count++;
            am_sum += n;
        }
    }
    /* count=2=0x02, sum_mod=0xF8, n_tests=101=0x65 → 0x6502F8 */
    g_result = (101u << 16) | ((am_count & 0xFFu) << 8) | (am_sum & 0xFFu);
}

void _start(void)
{
    test_amicable_numbers();
    while (1) {}
}
