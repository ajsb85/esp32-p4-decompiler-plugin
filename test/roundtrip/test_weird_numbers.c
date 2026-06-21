/* test_weird_numbers.c
 * Purpose   : Find weird numbers up to WN_UPPER=100.
 *             A number is weird if it is abundant (sum of proper divisors > n)
 *             but not pseudoperfect (no subset of proper divisors sums to n).
 *             Only weird number <= 100: 70.
 *
 * Algorithm : For each candidate n:
 *   1. Collect proper divisors and compute their sum.
 *   2. If sum <= n, skip (not abundant).
 *   3. Subset-sum DP over proper divisors with boolean reachable[] array;
 *      if reachable[n], number is pseudoperfect (not weird).
 *   4. Otherwise count it as weird; track the first one found.
 *
 * Distinctive decompiler idioms:
 *   1. Proper-divisors loop: `for d=1..n-1 if n%d==0`
 *   2. Knapsack backward-sweep: `for s=n..d if reachable[s-d]`
 *   3. Abundance check: `div_sum > n` gate before DP
 *
 * n_tests      = 100   (WN_UPPER,    0x64)
 * first_weird  = 70    (            0x46)
 * wn_count     = 1     (            0x01)
 *
 * g_result = (WN_UPPER<<16) | (first_weird<<8) | wn_count = 0x644601
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define WN_UPPER   100u
#define WN_MAXDIV   64u   /* max proper divisors for n<=100 */

static uint32_t wn_divisors[WN_MAXDIV];
static uint8_t  wn_reach[WN_UPPER + 1u];

static uint32_t wn_is_weird(uint32_t n)
{
    uint32_t nd = 0u;
    uint32_t dsum = 0u;

    /* Collect proper divisors and their sum */
    for (uint32_t d = 1u; d < n; d++) {
        if (n % d == 0u) {
            if (nd < WN_MAXDIV) {
                wn_divisors[nd++] = d;
            }
            dsum += d;
        }
    }

    /* Not abundant → not weird */
    if (dsum <= n) return 0u;

    /* Subset-sum DP: can any subset of divisors sum to n? */
    for (uint32_t i = 0u; i <= n; i++) wn_reach[i] = 0u;
    wn_reach[0] = 1u;

    for (uint32_t i = 0u; i < nd; i++) {
        uint32_t d = wn_divisors[i];
        /* Backward sweep to keep each divisor usable at most once */
        for (uint32_t s = n; s >= d; s--) {
            if (wn_reach[s - d]) {
                wn_reach[s] = 1u;
            }
        }
    }

    /* Pseudoperfect if n is reachable */
    if (wn_reach[n]) return 0u;

    return 1u;  /* abundant + not pseudoperfect = weird */
}

void test_weird_numbers(void)
{
    uint32_t wn_count   = 0u;
    uint32_t first_weird = 0u;

    for (uint32_t n = 2u; n <= WN_UPPER; n++) {
        if (wn_is_weird(n)) {
            wn_count++;
            if (first_weird == 0u) first_weird = n;
        }
    }
    /* first_weird=70=0x46, wn_count=1=0x01, WN_UPPER=100=0x64 → 0x644601 */
    g_result = (WN_UPPER << 16) | ((first_weird & 0xFFu) << 8) | (wn_count & 0xFFu);
}

void _start(void)
{
    test_weird_numbers();
    while (1) {}
}
