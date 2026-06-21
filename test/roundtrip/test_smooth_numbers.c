/* test_smooth_numbers.c
 * Purpose   : Count and sum B-smooth numbers in a range.
 *             A positive integer n is B-smooth if all its prime factors are <= B.
 *             Here B=5, range [1..20].
 *
 * Algorithm : For each n in [1..20], trial-divide by 2, 3, 5 repeatedly.
 *             If the remainder is 1 after removing all factors <= 5, n is 5-smooth.
 *             5-smooth numbers: 1,2,3,4,5,6,8,9,10,12,15,16,18,20.
 *
 * Distinctive decompiler idioms:
 *   1. Trial division loop: `while (n%p==0) n/=p` for each small prime
 *   2. Smooth check: `if (rem==1) count++; sum+=orig`
 *   3. Outer range loop over [1..UPPER] with inner per-prime loop
 *
 * n_tests       = 20  (UPPER, 0x14)
 * count_smooth  = 14  (0x0E)
 * sum_low       = (1+2+3+4+5+6+8+9+10+12+15+16+18+20) & 0xFF = 129 & 0xFF = 0x81
 *
 * g_result = (n_tests<<16) | (count_smooth<<8) | sum_low = 0x140E81
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define SN_UPPER 20u    /* test range [1..20] */
#define SN_B     5u     /* smoothness bound */

/* Small primes up to B=5 */
static const uint32_t sn_primes[3] = {2u, 3u, 5u};

void test_smooth_numbers(void)
{
    uint32_t count_smooth = 0u;
    uint32_t sum_smooth   = 0u;

    for (uint32_t n = 1u; n <= SN_UPPER; n++) {
        uint32_t rem = n;
        /* Remove all factors <= B */
        for (uint32_t pi = 0u; pi < 3u; pi++) {
            uint32_t p = sn_primes[pi];
            while (rem % p == 0u) {
                rem /= p;
            }
        }
        if (rem == 1u) {
            count_smooth++;
            sum_smooth += n;
        }
    }
    /* count=14=0x0E, sum=129=0x81, UPPER=20=0x14 → 0x140E81 */
    g_result = (SN_UPPER << 16) | ((count_smooth & 0xFFu) << 8) | (sum_smooth & 0xFFu);
}

void _start(void)
{
    test_smooth_numbers();
    while (1) {}
}
