/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Levenshtein Edit Distance fixture.
 *
 * Classic O(nm) DP for minimum edit distance (insert/delete/substitute).
 *
 * Distinctive decompiler idioms:
 *   1. `dp[0][j]=j; dp[i][0]=i` — base case: cost of turning "" into prefix
 *   2. `if s1[i-1]==s2[j-1]: dp[i][j]=dp[i-1][j-1]` — match: no cost
 *   3. `else dp[i][j]=1+min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])` — insert/del/sub
 *   4. `return dp[m][n]` — final cell is the answer
 *
 * Test cases:
 *   "kitten" → "sitting" : distance = 3
 *   "sunday" → "saturday": distance = 3
 *   "abc"    → "yabd"    : distance = 2
 *
 * n_tests = 3
 * sum     = 3+3+2 = 8
 * xor     = 3^3^2 = 2
 *
 * g_result = (3<<16) | (8<<8) | 2 = 0x00030802
 */
#include <stdint.h>

volatile uint32_t g_result;

static int ed_min3(int a, int b, int c)
{
    int m = a < b ? a : b;
    return m < c ? m : c;
}

static int edit_dist(const char *s1, int m, const char *s2, int n)
{
    static int dp[16][16];
    for (int i = 0; i <= m; i++) dp[i][0] = i;
    for (int j = 0; j <= n; j++) dp[0][j] = j;
    for (int i = 1; i <= m; i++)
        for (int j = 1; j <= n; j++) {
            if (s1[i-1] == s2[j-1])
                dp[i][j] = dp[i-1][j-1];
            else
                dp[i][j] = 1 + ed_min3(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
        }
    return dp[m][n];
}

void test_edit_distance(void)
{
    int d1 = edit_dist("kitten",  6, "sitting",  7); /* 3 */
    int d2 = edit_dist("sunday",  6, "saturday", 8); /* 3 */
    int d3 = edit_dist("abc",     3, "yabd",     4); /* 2 */

    uint32_t s = (uint32_t)(d1 + d2 + d3);
    uint32_t x = (uint32_t)(d1 ^ d2 ^ d3);
    g_result = (3u << 16) | ((s & 0xFFu) << 8) | (x & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_edit_distance();
    for (;;);
}
