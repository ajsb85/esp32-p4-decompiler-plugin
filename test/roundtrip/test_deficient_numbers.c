/* test_deficient_numbers.c
 * Purpose   : For each n in [1..DN_UPPER], determine if n is deficient
 *             (sigma(n) < 2*n, where sigma is the sum of all divisors).
 *             Track count of deficients and their sum (mod 256).
 *             For DN_UPPER=50: count=39, sum_mod=203.
 *
 * Algorithm : Compute sigma(n) via trial-division inner loop, then compare
 *             to 2*n. Accumulate count and sum of qualifying n values.
 *
 * Distinctive decompiler idioms:
 *   1. Divisor-sum inner loop: `for d=1; d<=n; d++ if n%d==0 s+=d`
 *   2. Deficiency test: sigma < 2*n → count++, sum+=n
 *   3. Outer sweep with dual accumulators (count, sum)
 *
 * n_tests   = 50    (DN_UPPER, 0x32)
 * dn_count  = 39    (0x27)
 * sum_mod   = 203   (0xCB)
 *
 * g_result = (DN_UPPER<<16) | (dn_count<<8) | sum_mod = 0x3227CB
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define DN_UPPER 50u

static uint32_t dn_sigma(uint32_t n)
{
    uint32_t s = 0u;
    for (uint32_t d = 1u; d <= n; d++) {
        if (n % d == 0u) s += d;
    }
    return s;
}

void test_deficient_numbers(void)
{
    uint32_t dn_count = 0u;
    uint32_t dn_sum   = 0u;

    for (uint32_t n = 1u; n <= DN_UPPER; n++) {
        uint32_t sig = dn_sigma(n);
        if (sig < 2u * n) {
            dn_count++;
            dn_sum += n;
        }
    }
    /* dn_count=39=0x27, sum_mod=203=0xCB, DN_UPPER=50=0x32 → 0x3227CB */
    g_result = (DN_UPPER << 16) | ((dn_count & 0xFFu) << 8) | (dn_sum & 0xFFu);
}

void _start(void)
{
    test_deficient_numbers();
    while (1) {}
}
