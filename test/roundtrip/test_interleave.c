/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Interleaving Strings DP fixture.
 *
 * Checks if s3 is formed by interleaving s1 and s2 maintaining relative order.
 * DP: dp[i][j] = whether s3[0..i+j-1] is interleaving of s1[0..i-1], s2[0..j-1].
 *
 * Distinctive decompiler idioms:
 *   1. `dp[0][0]=1; dp[i][0]=dp[i-1][0]&&s1[i-1]==s3[i-1]` — base cases
 *   2. `dp[i][j] = (dp[i-1][j] && s1[i-1]==s3[i+j-1]) || (dp[i][j-1] && s2[j-1]==s3[i+j-1])`
 *   3. `return dp[n1][n2]` — final answer
 *
 * Test cases:
 *   1. s1="aab", s2="axy", s3="aaxaby"   → 1 (interleaving)
 *   2. s1="abc", s2="def", s3="abdecf"   → 1 (interleaving)
 *   3. s1="abc", s2="def", s3="abcfed"   → 0 (s2 reversed, not interleaving)
 *
 * n_true=2, weighted_xor = 1^1^2^0^3 = 1*(1) XOR 1*(2) XOR 0*(3) = 1^2 = 3
 * g_result = (3 << 16) | (2 << 8) | 3 = 0x00030203
 */
#include <stdint.h>

volatile uint32_t g_result;

#define IL_MAX1 4
#define IL_MAX2 4

static int il_dp[IL_MAX1 + 1][IL_MAX2 + 1];

static int is_interleave(const char *s1, int n1,
                         const char *s2, int n2,
                         const char *s3)
{
    il_dp[0][0] = 1;
    for (int i = 1; i <= n1; i++)
        il_dp[i][0] = il_dp[i-1][0] && (s1[i-1] == s3[i-1]);
    for (int j = 1; j <= n2; j++)
        il_dp[0][j] = il_dp[0][j-1] && (s2[j-1] == s3[j-1]);
    for (int i = 1; i <= n1; i++)
        for (int j = 1; j <= n2; j++)
            il_dp[i][j] = (il_dp[i-1][j] && s1[i-1] == s3[i+j-1])
                        || (il_dp[i][j-1] && s2[j-1] == s3[i+j-1]);
    return il_dp[n1][n2];
}

void test_interleave(void)
{
    int r1 = is_interleave("aab", 3, "axy", 3, "aaxaby"); /* 1 */
    int r2 = is_interleave("abc", 3, "def", 3, "abdecf"); /* 1 */
    int r3 = is_interleave("abc", 3, "def", 3, "abcfed"); /* 0 */

    int n_true       = r1 + r2 + r3;                     /* 2 */
    int weighted_xor = (r1 * 1) ^ (r2 * 2) ^ (r3 * 3);  /* 1^2^0 = 3 */

    g_result = (3u << 16)
             | ((uint32_t)(n_true & 0xFF) << 8)
             | ((uint32_t)(weighted_xor & 0xFF));
}

__attribute__((noreturn)) void _start(void)
{
    test_interleave();
    for (;;);
}
