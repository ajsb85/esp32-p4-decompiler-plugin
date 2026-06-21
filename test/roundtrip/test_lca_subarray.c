/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Common Subarray (contiguous) DP fixture.
 *
 * Finds the length of the longest contiguous subarray (subarray, not subsequence)
 * common to both arrays using:
 *   dp[i][j] = len of longest common subarray ending at a1[i-1] and a2[j-1]
 *   if a1[i-1]==a2[j-1]: dp[i][j]=dp[i-1][j-1]+1, else dp[i][j]=0
 *
 * Distinctive decompiler idioms:
 *   1. `dp[i][j] = (a1[i-1] == a2[j-1]) ? dp[i-1][j-1]+1 : 0`
 *   2. `if (dp[i][j] > max_len) max_len = dp[i][j]`
 *   3. Same structure as edit distance but simpler transitions
 *
 * Test cases:
 *   {1,2,3,2,1} / {3,2,1,4,7}: len=3 (3,2,1)
 *   {0,0,0,0,1} / {1,0,0,0,0}: len=4 (0,0,0,0)
 *   {1,2,3}     / {4,5,6}:     len=0 (no common)
 *   sum=7=0x07, xor=3^4^0=7=0x07
 *
 * g_result = (3 << 16) | (7 << 8) | 7 = 0x00030707
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LCSA_M 5
#define LCSA_N 5

static int lcsa_dp[LCSA_M + 1][LCSA_N + 1];

static int longest_common_subarray(const int *a1, int m, const int *a2, int n)
{
    int max_len = 0;
    for (int i = 0; i <= m; i++) lcsa_dp[i][0] = 0;
    for (int j = 0; j <= n; j++) lcsa_dp[0][j] = 0;
    for (int i = 1; i <= m; i++)
        for (int j = 1; j <= n; j++) {
            lcsa_dp[i][j] = (a1[i-1] == a2[j-1]) ? lcsa_dp[i-1][j-1] + 1 : 0;
            if (lcsa_dp[i][j] > max_len) max_len = lcsa_dp[i][j];
        }
    return max_len;
}

void test_lca_subarray(void)
{
    static const int a0[5] = {1, 2, 3, 2, 1};
    static const int b0[5] = {3, 2, 1, 4, 7};
    static const int a1[5] = {0, 0, 0, 0, 1};
    static const int b1[5] = {1, 0, 0, 0, 0};
    static const int a2[3] = {1, 2, 3};
    static const int b2[3] = {4, 5, 6};

    int r0 = longest_common_subarray(a0, 5, b0, 5); /* 3 */
    int r1 = longest_common_subarray(a1, 5, b1, 5); /* 4 */
    int r2 = longest_common_subarray(a2, 3, b2, 3); /* 0 */

    g_result = (3u << 16)
             | ((uint32_t)((r0 + r1 + r2) & 0xFF) << 8)
             | ((uint32_t)((r0 ^ r1 ^ r2) & 0xFF));
}

__attribute__((noreturn)) void _start(void)
{
    test_lca_subarray();
    for (;;);
}
