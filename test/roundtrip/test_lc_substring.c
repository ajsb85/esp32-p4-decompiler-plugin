/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Common Substring (DP) fixture.
 *
 * Find the length of the longest substring common to two strings.
 * O(m*n) DP — differs from LCS in that dp resets to 0 on mismatch:
 *
 *   dp[i][j] = (s1[i-1] == s2[j-1]) ? dp[i-1][j-1] + 1 : 0
 *   max_len  = max(max_len, dp[i][j])
 *
 * Distinctive idioms vs LCS subsequence (which uses max of neighbors):
 *   1. dp[i][j] = 0 on mismatch   ← reset vs max
 *   2. No dp[i-1][j] / dp[i][j-1] path computation
 *   3. Track max of dp[i][j] during fill
 *
 * s1 = "ABABC"  (m=5)
 * s2 = "BABCAB" (n=6)
 *
 * Longest common substring: "BABC" (length=4)
 *   s1[1..4] = "BABC"
 *   s2[0..3] = "BABC"
 *
 * m   = 5
 * n   = 6
 * lcs = 4
 *
 * g_result = (m << 16) | (n << 8) | lcs_len = 0x00050604
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Longest Common Substring ─────────────────────────────────────────────── */

#define LCS_M 5
#define LCS_N 6

static int lcs_dp[LCS_M + 1][LCS_N + 1];

static int lc_substring(const char *s1, const char *s2, int m, int n)
{
    int max_len = 0;
    for (int i = 0; i <= m; i++)
        for (int j = 0; j <= n; j++)
            lcs_dp[i][j] = 0;

    for (int i = 1; i <= m; i++) {
        for (int j = 1; j <= n; j++) {
            if (s1[i - 1] == s2[j - 1]) {
                lcs_dp[i][j] = lcs_dp[i - 1][j - 1] + 1;
                if (lcs_dp[i][j] > max_len)
                    max_len = lcs_dp[i][j];
            } else {
                lcs_dp[i][j] = 0;   /* reset — key difference from LCS */
            }
        }
    }
    return max_len;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_lc_substring(void)
{
    static const char s1[] = "ABABC";
    static const char s2[] = "BABCAB";

    int lcs = lc_substring(s1, s2, LCS_M, LCS_N);
    /* lcs=4 ("BABC") */

    g_result = ((uint32_t)LCS_M << 16)
             | ((uint32_t)LCS_N << 8)
             | (uint32_t)lcs;
}

__attribute__((noreturn)) void _start(void)
{
    test_lc_substring();
    for (;;);
}
