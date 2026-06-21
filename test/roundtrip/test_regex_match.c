/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Regular Expression Matching (DP) fixture.
 *
 * Implements full regex matching with two special characters:
 *   '.' — matches any single character
 *   '*' — matches zero or more of the preceding element
 *
 * DP: dp[i][j] = true iff s[0..i-1] is fully matched by p[0..j-1].
 *
 * Distinctive decompiler idioms:
 *   1. `dp[0][0] = 1` — empty string matches empty pattern
 *   2. `dp[0][j] = dp[0][j-2] && p[j-1]=='*'` — star eliminates pairs at start
 *   3. `if p[j-1]=='*': dp[i][j] = dp[i][j-2] | (dp[i-1][j] & char_match)` — star rule
 *   4. `else: dp[i][j] = dp[i-1][j-1] & char_match` — literal/dot rule
 *
 * Test cases:
 *   "aa"          vs "a*"          → 1 (a* matches zero+ a's)
 *   "ab"          vs ".*"          → 1 (.* matches any string)
 *   "aab"         vs "c*a*b"       → 1 (c* matches zero c's, a* matches "aa")
 *   "mississippi" vs "mis*is*p*."  → 0 (classic false-positive trap)
 *
 * n_tests    = 4
 * sum_match  = 1+1+1+0 = 3  (0x03)
 * xor_match  = 1^1^1^0      = 1  (0x01)
 *
 * g_result = (4 << 16) | (3 << 8) | 1 = 0x00040301
 */
#include <stdint.h>

volatile uint32_t g_result;

#define RM_MAXS 12
#define RM_MAXP 12

static int rm_dp[RM_MAXS][RM_MAXP];

static int rm_strlen(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static int regex_match(const char *s, const char *p)
{
    int ls = rm_strlen(s), lp = rm_strlen(p);

    for (int i = 0; i <= ls; i++)
        for (int j = 0; j <= lp; j++)
            rm_dp[i][j] = 0;

    rm_dp[0][0] = 1;
    for (int j = 2; j <= lp; j++)
        if (p[j-1] == '*')
            rm_dp[0][j] = rm_dp[0][j-2];

    for (int i = 1; i <= ls; i++) {
        for (int j = 1; j <= lp; j++) {
            if (p[j-1] == '*') {
                rm_dp[i][j] = rm_dp[i][j-2]; /* zero occurrences */
                if (j >= 2 && (s[i-1] == p[j-2] || p[j-2] == '.'))
                    rm_dp[i][j] |= rm_dp[i-1][j]; /* one-or-more occurrences */
            } else {
                int char_match = (s[i-1] == p[j-1] || p[j-1] == '.');
                rm_dp[i][j] = rm_dp[i-1][j-1] & char_match;
            }
        }
    }
    return rm_dp[ls][lp];
}

static const char rm_s1[] = "aa";           static const char rm_p1[] = "a*";
static const char rm_s2[] = "ab";           static const char rm_p2[] = ".*";
static const char rm_s3[] = "aab";          static const char rm_p3[] = "c*a*b";
static const char rm_s4[] = "mississippi";  static const char rm_p4[] = "mis*is*p*.";

void test_regex_match(void)
{
    int r1 = regex_match(rm_s1, rm_p1); /* 1 */
    int r2 = regex_match(rm_s2, rm_p2); /* 1 */
    int r3 = regex_match(rm_s3, rm_p3); /* 1 */
    int r4 = regex_match(rm_s4, rm_p4); /* 0 */

    uint32_t sum_m = (uint32_t)(r1 + r2 + r3 + r4); /* 3 */
    uint32_t xor_m = (uint32_t)(r1 ^ r2 ^ r3 ^ r4); /* 1 */

    g_result = (4u << 16) | ((sum_m & 0xFFu) << 8) | (xor_m & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_regex_match();
    for (;;);
}
