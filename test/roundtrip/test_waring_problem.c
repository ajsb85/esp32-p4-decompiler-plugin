/* test_waring_problem.c
 * Purpose   : Waring's problem — minimum number of perfect squares needed to
 *             represent each positive integer (g(2) = 4 by Lagrange's theorem).
 * Algorithm : DP: min_sq[0] = 0; for each n from 1..N, try all perfect
 *             squares k^2 <= n: min_sq[n] = min(min_sq[n], min_sq[n-k^2]+1).
 *
 * Distinctive decompiler idioms:
 *   1. Inner loop over squares: `for (k=1; k*k<=n; k++) if(dp[n-k*k]+1 < dp[n]) ...`
 *   2. Initialise with sentinel: `dp[n] = n` (worst case: n×1²)
 *   3. g(2)=4 Lagrange four-square theorem: max dp value is 4 (for n=7)
 *
 * Sequence (n=1..10): 1,2,3,1,2,3,4,2,1,2
 *   (e.g. 7 = 4+1+1+1 → 4 squares; 9 = 9 → 1 square)
 *
 * n_tests = 10
 * dp_sum  = 1+2+3+1+2+3+4+2+1+2 = 21  (0x15)
 * dp_max  = 4                          (0x04)
 *
 * g_result = (n_tests<<16) | (dp_sum<<8) | dp_max
 *          = (10<<16) | (21<<8) | 4
 *          = 0x0A1504
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define WP_N 10u

static uint32_t wp_dp[WP_N + 1u];

void test_waring_problem(void)
{
    wp_dp[0] = 0u;
    for (uint32_t n = 1u; n <= WP_N; n++) {
        wp_dp[n] = n;  /* worst case: n copies of 1^2 */
        for (uint32_t k = 1u; k * k <= n; k++) {
            uint32_t candidate = wp_dp[n - k * k] + 1u;
            if (candidate < wp_dp[n]) {
                wp_dp[n] = candidate;
            }
        }
    }

    uint32_t dp_sum = 0u;
    uint32_t dp_max = 0u;
    for (uint32_t n = 1u; n <= WP_N; n++) {
        dp_sum += wp_dp[n];
        if (wp_dp[n] > dp_max) dp_max = wp_dp[n];
    }
    /* dp_sum=21=0x15, dp_max=4=0x04, WP_N=10=0x0A → 0x0A1504 */
    g_result = (WP_N << 16) | ((dp_sum & 0xFFu) << 8) | (dp_max & 0xFFu);
}

void _start(void)
{
    test_waring_problem();
    while (1) {}
}
