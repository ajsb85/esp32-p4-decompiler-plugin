/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Palindromic Subsequence (LPS) interval DP fixture.
 *
 * Interval DP computing dp[i][j] = length of longest palindromic subsequence
 * of s[i..j] (both ends inclusive).
 *
 * Recurrence:
 *   dp[i][i]   = 1                              (single character)
 *   dp[i][i+1] = 2 if s[i]==s[i+1] else 1      (two characters)
 *   dp[i][j]   = dp[i+1][j-1] + 2  if s[i]==s[j]
 *              = max(dp[i+1][j], dp[i][j-1])    otherwise
 *
 * Diagonal filling order (by increasing length):
 *   for len in 2..n:
 *     for i in 0..n-len:
 *       j = i + len - 1
 *       ...
 *
 * Input: "BBABCBCAB" (n=9)
 *   LPS = "BABCBAB" (length 7), verified: B(1)A(2)B(3)C(4)B(5)A(7)B(8)
 *
 *   lps   = dp[0][8] = 7
 *   n     = 9
 *   n-lps = 2  (minimum insertions to make palindrome)
 *
 * g_result = (n << 16) | (lps << 8) | (n - lps) = 0x00090702
 *
 * Recognizable decompiler idioms:
 *   dp[i][j] = (s[i]==s[j]) ? dp[i+1][j-1]+2 : max(dp[i+1][j], dp[i][j-1])
 *   for(len=2; len<=n; len++) for(i=0; i<=n-len; i++) j=i+len-1
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── LPS interval DP ─────────────────────────────────────────────────────── */

#define LPS_N 9

static int lps_dp[LPS_N][LPS_N];

static int lps_compute(const char *s, int n)
{
    for (int i = 0; i < n; i++) lps_dp[i][i] = 1;

    for (int len = 2; len <= n; len++) {
        for (int i = 0; i <= n - len; i++) {
            int j = i + len - 1;
            if (s[i] == s[j]) {
                lps_dp[i][j] = (len == 2) ? 2 : lps_dp[i + 1][j - 1] + 2;
            } else {
                int a = lps_dp[i + 1][j];
                int b = lps_dp[i][j - 1];
                lps_dp[i][j] = (a > b) ? a : b;
            }
        }
    }
    return lps_dp[0][n - 1];
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_lps(void)
{
    static const char s[LPS_N + 1] = "BBABCBCAB";
    int lps = lps_compute(s, LPS_N);   /* = 7 */

    g_result = ((uint32_t)LPS_N << 16)
             | ((uint32_t)lps << 8)
             | ((uint32_t)(LPS_N - lps) & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_lps();
    for (;;);
}
