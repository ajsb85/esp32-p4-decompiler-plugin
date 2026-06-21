#include <stdint.h>
#include <string.h>

/* Longest Common Subsequence of two strings.
 * dp[i][j] = LCS length for s1[0..i-1] and s2[0..j-1].
 * g_result encodes (n_tests, sum_lcs_lengths, xor_lcs_lengths). */

static int imax(int a, int b) { return a > b ? a : b; }

static int lcs(const char *s1, const char *s2) {
    int m = (int)strlen(s1), n = (int)strlen(s2);
    int dp[8][8];
    for (int i = 0; i <= m; i++) dp[i][0] = 0;
    for (int j = 0; j <= n; j++) dp[0][j] = 0;
    for (int i = 1; i <= m; i++)
        for (int j = 1; j <= n; j++)
            dp[i][j] = (s1[i-1] == s2[j-1]) ?
                        dp[i-1][j-1] + 1 :
                        imax(dp[i-1][j], dp[i][j-1]);
    return dp[m][n];
}

volatile uint32_t g_result;

void test_lcs(void) {
    int r1 = lcs("ABCBDAB", "BDCAB");     /* 4 */
    int r2 = lcs("AGGTAB",  "GXTXAYB");  /* 4 */
    int r3 = lcs("abc",     "abc");       /* 3 */
    int s  = r1 + r2 + r3;  /* 11 */
    int x  = r1 ^ r2 ^ r3;  /* 3  */
    g_result = (3u << 16) | ((uint32_t)s << 8) | (uint32_t)x; /* 0x00030B03 */
}

__attribute__((noreturn)) void _start(void) {
    test_lcs();
    for (;;);
}
