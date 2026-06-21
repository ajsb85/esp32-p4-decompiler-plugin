/* test_abundant_numbers.c
 * Purpose   : Find and sum abundant numbers in the range [1..50].
 *             A number n is abundant if sigma(n) > n (proper-divisor sum exceeds n).
 *             Abundant in [1..50]: 12,18,20,24,30,36,40,42,48 → 9 values, sum=270.
 *
 * Algorithm : For each n in [1..50], compute sigma(n) = sum of proper divisors.
 *             If sigma(n) > n, increment count and add n to sum.
 *
 * Distinctive decompiler idioms:
 *   1. Proper-divisor loop: `for d=1; d<n; d++` with `if n%d==0 s+=d`
 *   2. Abundance test: `if (sigma > n) count++; total += n`
 *   3. Tight outer loop [1..UPPER] with inner divisor scan
 *
 * n_tests   = 50    (UPPER, 0x32)
 * ab_count  = 9     (0x09)
 * sum_mod   = 14    (270 & 0xFF = 0x0E)
 *
 * g_result = (UPPER<<16) | (ab_count<<8) | sum_mod = 0x32090E
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define AB_UPPER 50u

static uint32_t ab_sigma(uint32_t n)
{
    uint32_t s = 0u;
    for (uint32_t d = 1u; d < n; d++) {
        if (n % d == 0u) {
            s += d;
        }
    }
    return s;
}

void test_abundant_numbers(void)
{
    uint32_t ab_count = 0u;
    uint32_t ab_sum   = 0u;

    for (uint32_t n = 1u; n <= AB_UPPER; n++) {
        if (ab_sigma(n) > n) {
            ab_count++;
            ab_sum += n;
        }
    }
    /* count=9=0x09, sum_mod=0x0E, UPPER=50=0x32 → 0x32090E */
    g_result = (AB_UPPER << 16) | ((ab_count & 0xFFu) << 8) | (ab_sum & 0xFFu);
}

void _start(void)
{
    test_abundant_numbers();
    while (1) {}
}
