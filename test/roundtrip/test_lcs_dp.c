/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Common Subsequence (LCS) DP fixture.
 *
 * Classic O(mn) DP:
 *   dp[i][j] = LCS length of s1[:i] and s2[:j]
 *   dp[i][j] = dp[i-1][j-1]+1 if s1[i-1]==s2[j-1], else max(dp[i-1][j], dp[i][j-1])
 *
 * Distinctive decompiler idioms:
 *   1. `if (s1[i-1] == s2[j-1]) dp[i][j] = dp[i-1][j-1] + 1`
 *   2. `else dp[i][j] = max(dp[i-1][j], dp[i][j-1])`
 *   3. `return dp[m][n]` — bottom-right cell is the answer
 *
 * Test cases:
 *   "ABCBDAB" / "BDCAB"   → 4
 *   "AGGTAB"  / "GXTXAYB" → 4
 *   "ABC"     / "AC"      → 2
 *   sum=10=0x0A, xor=4^4^2=2=0x02
 *
 * g_result = (3 << 16) | (10 << 8) | 2 = 0x00030A02
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LCS_M 8
#define LCS_N 8

static int lcs_dp[LCS_M + 1][LCS_N + 1];

static int lcs_len(const char *s1, int m, const char *s2, int n)
{
    for (int i = 0; i <= m; i++) lcs_dp[i][0] = 0;
    for (int j = 0; j <= n; j++) lcs_dp[0][j] = 0;
    for (int i = 1; i <= m; i++)
        for (int j = 1; j <= n; j++) {
            if (s1[i-1] == s2[j-1])
                lcs_dp[i][j] = lcs_dp[i-1][j-1] + 1;
            else
                lcs_dp[i][j] = lcs_dp[i-1][j] > lcs_dp[i][j-1]
                              ? lcs_dp[i-1][j] : lcs_dp[i][j-1];
        }
    return lcs_dp[m][n];
}

void test_lcs_dp(void)
{
    int r0 = lcs_len("ABCBDAB", 7, "BDCAB",   5); /* 4 */
    int r1 = lcs_len("AGGTAB",  6, "GXTXAYB", 7); /* 4 */
    int r2 = lcs_len("ABC",     3, "AC",       2); /* 2 */

    g_result = (3u << 16)
             | ((uint32_t)((r0 + r1 + r2) & 0xFF) << 8)
             | ((uint32_t)((r0 ^ r1 ^ r2) & 0xFF));
}

__attribute__((noreturn)) void _start(void)
{
    test_lcs_dp();
    for (;;);
}
