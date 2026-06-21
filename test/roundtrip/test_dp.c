/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Dynamic Programming (LCS) round-trip fixture.
 *
 * Implements the classic 2D Longest-Common-Subsequence DP.  The nested
 * for-loops filling a 2D table with max(dp[i-1][j], dp[i][j-1]) vs
 * dp[i-1][j-1]+1 are among the most identifiable DP patterns in decompiled
 * output.
 *
 * Strings:
 *   a = "ABCBDAB"   (len=7)
 *   b = "BDCAB"     (len=5)
 *
 * LCS table (rows = a, cols = b):
 *         ""  B  D  C  A  B
 *    ""    0  0  0  0  0  0
 *    A     0  0  0  0  1  1
 *    B     0  1  1  1  1  2
 *    C     0  1  1  2  2  2
 *    B     0  1  1  2  2  3
 *    D     0  1  2  2  2  3
 *    A     0  1  2  2  3  3
 *    B     0  1  2  2  3  4
 *
 * LCS length = dp[7][5] = 4  (e.g. "BCAB" or "BDAB")
 *
 * g_result = (len_a << 16) | (len_b << 8) | lcs_len
 *           = (7 << 16) | (5 << 8) | 4 = 0x00070504
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── LCS via bottom-up 2D DP ─────────────────────────────────────────────── */

static int lcs_len(const char *a, int la, const char *b, int lb)
{
    static int dp[8][6]; /* dp[i][j] = LCS(a[0..i-1], b[0..j-1]) */

    for (int i = 0; i <= la; i++) dp[i][0] = 0;
    for (int j = 0; j <= lb; j++) dp[0][j] = 0;

    for (int i = 1; i <= la; i++) {
        for (int j = 1; j <= lb; j++) {
            if (a[i - 1] == b[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                int left = dp[i][j - 1];
                int up   = dp[i - 1][j];
                dp[i][j] = left > up ? left : up;
            }
        }
    }

    return dp[la][lb];
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_dp(void)
{
    static const char a[] = "ABCBDAB"; /* len 7 */
    static const char b[] = "BDCAB";   /* len 5 */

    int la = 7, lb = 5;
    int lcs = lcs_len(a, la, b, lb);

    g_result = ((uint32_t)la << 16)
             | ((uint32_t)lb << 8)
             | ((uint32_t)lcs & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_dp();
    for (;;);
}
