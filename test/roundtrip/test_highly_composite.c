/* test_highly_composite.c
 * Purpose   : Find highly composite numbers in [1..100].
 *             A number n is highly composite if it has more divisors than every
 *             positive integer smaller than n.
 *             HC numbers in [1..100]: 1,2,4,6,12,24,36,48,60 → 9 values, sum=193.
 *
 * Algorithm : Scan n in [1..HC_UPPER]; compute divisor count; if it exceeds the
 *             running maximum, record n as highly composite.
 *
 * Distinctive decompiler idioms:
 *   1. Inner divisor-count loop: `for d=1; d<=n; d++ if n%d==0 cnt++`
 *   2. Running maximum comparison: `if (cnt > max_div) { max_div=cnt; ... }`
 *   3. Outer linear scan accumulating count and sum
 *
 * n_tests   = 100   (HC_UPPER, 0x64)
 * hc_count  = 9     (0x09)
 * sum_mod   = 193   (193 & 0xFF = 0xC1)
 *
 * g_result = (HC_UPPER<<16) | (hc_count<<8) | sum_mod = 0x6409C1
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define HC_UPPER 100u

static uint32_t hc_divisor_count(uint32_t n)
{
    uint32_t cnt = 0u;
    for (uint32_t d = 1u; d <= n; d++) {
        if (n % d == 0u) cnt++;
    }
    return cnt;
}

void test_highly_composite(void)
{
    uint32_t hc_count = 0u;
    uint32_t hc_sum   = 0u;
    uint32_t max_div  = 0u;

    for (uint32_t n = 1u; n <= HC_UPPER; n++) {
        uint32_t cnt = hc_divisor_count(n);
        if (cnt > max_div) {
            max_div = cnt;
            hc_count++;
            hc_sum += n;
        }
    }
    /* count=9=0x09, sum_mod=0xC1, HC_UPPER=100=0x64 → 0x6409C1 */
    g_result = (HC_UPPER << 16) | ((hc_count & 0xFFu) << 8) | (hc_sum & 0xFFu);
}

void _start(void)
{
    test_highly_composite();
    while (1) {}
}
