/* test_practical_numbers.c
 * Purpose   : Identify practical numbers up to PN_UPPER=60.
 *             A practical number n is one where every integer 1..n
 *             can be represented as a sum of distinct divisors of n.
 *             Practical numbers up to 60:
 *             1,2,4,6,8,12,16,18,20,24,28,30,32,36,40,42,48,54,56,60 (count=20).
 *
 * Algorithm : For each candidate n, enumerate all divisors (including n itself),
 *             then run a 0/1 knapsack backward sweep over a reachable[] boolean
 *             array to test whether every value 1..n is covered.
 *
 * Distinctive decompiler idioms:
 *   1. Full-divisors loop: `for d=1..n if n%d==0`
 *   2. Knapsack backward-sweep: `for s=n..d if reachable[s-d]`
 *   3. Coverage check: `for k=1..n if !reachable[k] return false`
 *
 * n_tests          = 60  (PN_UPPER, 0x3C)
 * pn_count         = 20  (          0x14)
 * second_practical = 2   (          0x02)
 *
 * g_result = (PN_UPPER<<16) | (pn_count<<8) | second_practical = 0x3C1402
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define PN_UPPER  60u
#define PN_MAXDIV 16u   /* max divisors for n<=60 */

static uint32_t pn_divisors[PN_MAXDIV];
static uint8_t  pn_reach[PN_UPPER + 1u];

static uint32_t pn_is_practical(uint32_t n)
{
    uint32_t nd = 0u;

    /* Collect all divisors of n (including n itself) */
    for (uint32_t d = 1u; d <= n; d++) {
        if (n % d == 0u) {
            if (nd < PN_MAXDIV) {
                pn_divisors[nd++] = d;
            }
        }
    }

    /* Initialize reachable sums to 0 */
    for (uint32_t i = 0u; i <= n; i++) pn_reach[i] = 0u;
    pn_reach[0] = 1u;

    /* 0/1 knapsack: each divisor used at most once */
    for (uint32_t i = 0u; i < nd; i++) {
        uint32_t d = pn_divisors[i];
        for (uint32_t s = n; s >= d; s--) {
            if (pn_reach[s - d]) {
                pn_reach[s] = 1u;
            }
        }
    }

    /* Check every 1..n is reachable */
    for (uint32_t k = 1u; k <= n; k++) {
        if (!pn_reach[k]) return 0u;
    }
    return 1u;
}

void test_practical_numbers(void)
{
    uint32_t pn_count        = 0u;
    uint32_t second_practical = 0u;
    uint32_t found_first     = 0u;

    for (uint32_t n = 1u; n <= PN_UPPER; n++) {
        if (pn_is_practical(n)) {
            pn_count++;
            if (found_first) {
                if (second_practical == 0u) {
                    second_practical = n;
                }
            } else {
                found_first = 1u;
            }
        }
    }
    /* pn_count=20=0x14, second_practical=2=0x02, PN_UPPER=60=0x3C → 0x3C1402 */
    g_result = (PN_UPPER << 16) | ((pn_count & 0xFFu) << 8) | (second_practical & 0xFFu);
}

void _start(void)
{
    test_practical_numbers();
    while (1) {}
}
