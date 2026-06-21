/* test_sociable_numbers.c
 * Purpose   : Find amicable-pair numbers (a special case of sociable numbers)
 *             in the range [2..300].  A pair (a,b) is amicable when
 *             s(a)=b and s(b)=a, with a≠b, where s(n) = sum of proper divisors.
 *             Count how many values ≤ 300 belong to at least one amicable pair,
 *             and accumulate their sum mod 256.
 *
 *             For N=300: the only amicable pair is (220, 284).
 *             count_amicable = 2, sum_mod = (220+284) % 256 = 504 % 256 = 248.
 *
 * Algorithm : For each a in [2..N], compute s(a).  If s(a)≠a and s(a)>1
 *             and s(s(a))==a, mark both a and s(a) as amicable.
 *
 * Distinctive decompiler idioms:
 *   1. Proper-divisor sum with sqrt-bounded inner loop
 *   2. Double-check: s(s(a)) == a with guard s(a)!=a
 *   3. Outer accumulator tracks count + running sum of amicable values
 *
 * n_tests   = 300   (0x012C  — upper scan limit)
 * count     =   2   (0x02    — amicable numbers ≤ 300)
 * sum_mod   = 248   (0xF8    — (220+284) mod 256)
 *
 * g_result  = (300<<16) | (2<<8) | 248 = 0x012C02F8
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define SOC_UPPER 300u

static uint32_t soc_proper_sum(uint32_t n)
{
    if (n <= 1u) return 0u;
    uint32_t s = 1u;
    uint32_t d = 2u;
    while (d * d <= n) {
        if (n % d == 0u) {
            s += d;
            if (d != n / d) s += n / d;
        }
        d++;
    }
    return s;
}

void test_sociable_numbers(void)
{
    uint32_t count   = 0u;
    uint32_t sum_acc = 0u;

    for (uint32_t a = 2u; a <= SOC_UPPER; a++) {
        uint32_t b = soc_proper_sum(a);
        if (b != a && b > 1u && soc_proper_sum(b) == a) {
            /* a is part of an amicable pair */
            count++;
            sum_acc += a;
        }
    }

    /* count=2=0x02, sum_mod=248=0xF8, SOC_UPPER=300=0x012C
     * g_result = (300<<16)|(2<<8)|248 = 0x012C02F8 */
    g_result = (SOC_UPPER << 16) | ((count & 0xFFu) << 8) | (sum_acc & 0xFFu);
}

void _start(void)
{
    test_sociable_numbers();
    while (1) {}
}
