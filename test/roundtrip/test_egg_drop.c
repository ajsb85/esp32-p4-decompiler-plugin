/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Egg Drop Problem (DP on floors testable) fixture.
 *
 * Classic DP formulation: dp[t][e] = maximum number of floors testable
 * with exactly t trials and e eggs (worst-case guarantee).
 *
 * Recurrence: dp[t][e] = dp[t-1][e-1] + dp[t-1][e] + 1
 *   (drop from floor dp[t-1][e-1]+1; if breaks: test below; if survives: test above)
 *
 * Base cases: dp[t][1] = t (linear scan with one egg); dp[0][e] = 0.
 *
 * Distinctive decompiler idioms:
 *   1. `dp[t][e] = dp[t-1][e-1] + dp[t-1][e] + 1` — 2D DP recurrence
 *   2. `for(t=1; dp[t][e] < n; t++)` — find minimum t by scanning
 *   3. Answer is t when dp[t][e] first >= n floors
 *
 * Test cases (min trials for n floors, e eggs):
 *   n=10,  e=2 → 4   (dp[4][2] = 4*5/2 = 10 ≥ 10)
 *   n=100, e=2 → 14  (dp[14][2] = 105 ≥ 100)
 *   n=36,  e=3 → 6   (dp[6][3] = 41 ≥ 36)
 *
 * n_tests   = 3
 * sum_trials = 4+14+6 = 24  (0x18)
 * xor_trials = 4^14^6       = 12  (0x0C)
 *
 * g_result = (3 << 16) | (24 << 8) | 12 = 0x0003180C
 */
#include <stdint.h>

volatile uint32_t g_result;

#define ED_MAX_T 20
#define ED_MAX_E 3

static int ed_dp[ED_MAX_T + 1][ED_MAX_E + 1];

static int egg_min_trials(int n, int e)
{
    for (int t = 1; t <= ED_MAX_T; t++)
        if (ed_dp[t][e] >= n)
            return t;
    return -1;
}

void test_egg_drop(void)
{
    /* base cases */
    for (int ee = 0; ee <= ED_MAX_E; ee++) ed_dp[0][ee] = 0;
    for (int t = 1; t <= ED_MAX_T; t++) {
        ed_dp[t][0] = 0;
        ed_dp[t][1] = t;
    }

    /* fill table */
    for (int t = 1; t <= ED_MAX_T; t++)
        for (int ee = 2; ee <= ED_MAX_E; ee++)
            ed_dp[t][ee] = ed_dp[t-1][ee-1] + ed_dp[t-1][ee] + 1;

    int t1 = egg_min_trials(10,  2); /*  4 */
    int t2 = egg_min_trials(100, 2); /* 14 */
    int t3 = egg_min_trials(36,  3); /*  6 */

    uint32_t sum_t = (uint32_t)(t1 + t2 + t3); /* 24 */
    uint32_t xor_t = (uint32_t)(t1 ^ t2 ^ t3); /* 12 */

    g_result = (3u << 16) | ((sum_t & 0xFFu) << 8) | (xor_t & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_egg_drop();
    for (;;);
}
