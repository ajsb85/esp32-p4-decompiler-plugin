/* test_liouville_function.c
 * Purpose   : Compute the Liouville function λ(n) = (-1)^Ω(n) for each n in [1..56],
 *             where Ω(n) is the total number of prime factors counted with multiplicity.
 *             Count how many values give λ(n)=+1 (even Ω) and how many give λ(n)=-1 (odd Ω).
 *
 *             For N=56:
 *               count_pos = 26  (n where Ω(n) is even)
 *               count_neg = 30  (n where Ω(n) is odd)
 *
 * Algorithm : Trial division to count total prime factors with multiplicity (Ω(n)),
 *             then test parity of count.
 *
 * Distinctive decompiler idioms:
 *   1. Big-Omega counter: inner while-loop dividing out each prime factor
 *   2. Parity test on prime-factor count: omega & 1
 *   3. Dual-counter accumulation for +1 / -1 results
 *
 * n_tests   = 56   (0x38 — range [1..56])
 * count_pos = 26   (0x1A — λ(n) = +1)
 * count_neg = 30   (0x1E — λ(n) = -1)
 *
 * g_result  = (56<<16) | (26<<8) | 30 = 0x381A1E
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define LV_UPPER 56u

static uint32_t big_omega(uint32_t n)
{
    uint32_t count = 0u;
    uint32_t d     = 2u;
    while (d * d <= n) {
        while (n % d == 0u) {
            count++;
            n /= d;
        }
        d++;
    }
    if (n > 1u) count++;
    return count;
}

void test_liouville_function(void)
{
    uint32_t count_pos = 0u;
    uint32_t count_neg = 0u;

    for (uint32_t n = 1u; n <= LV_UPPER; n++) {
        uint32_t omega = big_omega(n);
        if (omega & 1u) {
            count_neg++;   /* Ω(n) odd  → λ(n) = -1 */
        } else {
            count_pos++;   /* Ω(n) even → λ(n) = +1 */
        }
    }

    /* count_pos=26=0x1A, count_neg=30=0x1E, LV_UPPER=56=0x38
     * g_result = (56<<16)|(26<<8)|30 = 0x381A1E */
    g_result = (LV_UPPER << 16) | ((count_pos & 0xFFu) << 8) | (count_neg & 0xFFu);
}

void _start(void)
{
    test_liouville_function();
    while (1) {}
}
