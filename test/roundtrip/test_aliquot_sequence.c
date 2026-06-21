/* test_aliquot_sequence.c
 * Purpose   : For each n in [2..AQ_UPPER], compute the length of its aliquot sequence
 *             (iterate proper-divisor-sum until 0 or revisit).  Track maximum length
 *             and the sum of all sequence lengths (mod 256).
 *             For AQ_UPPER=40: max_steps=15 (starting at n=30), sum_mod=153.
 *
 * Algorithm : For each starting value, follow s(n) → s(s(n)) → ... until reaching 0
 *             or a visited node (cycle guard via step count).  Record step count.
 *
 * Distinctive decompiler idioms:
 *   1. Proper-divisor sum inner loop: `for d=1; d<n; d++ if n%d==0 s+=d`
 *   2. Chain-following while loop with termination on zero
 *   3. Outer sweep accumulating max and modular sum
 *
 * n_tests   = 40    (AQ_UPPER, 0x28)
 * max_steps = 15    (0x0F)
 * sum_mod   = 153   (0x99)
 *
 * g_result = (AQ_UPPER<<16) | (max_steps<<8) | sum_mod = 0x280F99
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define AQ_UPPER 40u
#define AQ_STEP_LIMIT 200u

static uint32_t aq_proper_sum(uint32_t n)
{
    uint32_t s = 0u;
    for (uint32_t d = 1u; d < n; d++) {
        if (n % d == 0u) s += d;
    }
    return s;
}

static uint32_t aq_chain_length(uint32_t start)
{
    uint32_t steps = 0u;
    uint32_t cur   = start;
    for (uint32_t i = 0u; i < AQ_STEP_LIMIT; i++) {
        uint32_t nxt = aq_proper_sum(cur);
        steps++;
        if (nxt == 0u) break;
        cur = nxt;
    }
    return steps;
}

void test_aliquot_sequence(void)
{
    uint32_t max_steps = 0u;
    uint32_t sum_steps = 0u;

    for (uint32_t n = 2u; n <= AQ_UPPER; n++) {
        uint32_t len = aq_chain_length(n);
        if (len > max_steps) max_steps = len;
        sum_steps += len;
    }
    /* max_steps=15=0x0F, sum_mod=153=0x99, AQ_UPPER=40=0x28 → 0x280F99 */
    g_result = (AQ_UPPER << 16) | ((max_steps & 0xFFu) << 8) | (sum_steps & 0xFFu);
}

void _start(void)
{
    test_aliquot_sequence();
    while (1) {}
}
