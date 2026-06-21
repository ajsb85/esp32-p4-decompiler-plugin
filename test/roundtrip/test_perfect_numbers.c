/* test_perfect_numbers.c
 * Purpose   : Find and sum perfect numbers in the range [1..100].
 *             A perfect number equals the sum of its proper divisors.
 *             Perfect numbers in [1..100]: 6 (1+2+3=6), 28 (1+2+4+7+14=28).
 *
 * Algorithm : For each n in [1..100], compute sigma(n) = sum of proper divisors
 *             by trial division up to n/2.  If sigma(n) == n, n is perfect.
 *
 * Distinctive decompiler idioms:
 *   1. Proper-divisor sum loop: `for d=1; d<=n/2; d++` with `if n%d==0 sum+=d`
 *   2. Equality check: `if (div_sum == n) count++; total += n`
 *   3. Outer sweep: `for n=1; n<=UPPER; n++`
 *
 * n_tests   = 100   (UPPER, 0x64)
 * pf_count  = 2     (0x02)
 * pf_sum    = 34    (6+28=34, 0x22)
 *
 * g_result = (UPPER<<16) | (pf_count<<8) | pf_sum = 0x640222
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define PF_UPPER 100u

static uint32_t proper_divisor_sum(uint32_t n)
{
    if (n < 2u) return 0u;
    uint32_t s = 1u;                   /* 1 is always a proper divisor for n>1 */
    for (uint32_t d = 2u; d <= n / 2u; d++) {
        if (n % d == 0u) {
            s += d;
        }
    }
    return s;
}

void test_perfect_numbers(void)
{
    uint32_t pf_count = 0u;
    uint32_t pf_sum   = 0u;

    for (uint32_t n = 1u; n <= PF_UPPER; n++) {
        if (proper_divisor_sum(n) == n) {
            pf_count++;
            pf_sum += n;
        }
    }
    /* count=2=0x02, sum=34=0x22, UPPER=100=0x64 → 0x640222 */
    g_result = (PF_UPPER << 16) | ((pf_count & 0xFFu) << 8) | (pf_sum & 0xFFu);
}

void _start(void)
{
    test_perfect_numbers();
    while (1) {}
}
