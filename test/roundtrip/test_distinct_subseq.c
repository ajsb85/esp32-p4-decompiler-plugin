#include <stdint.h>

/* Count distinct subsequences of s that equal t.
 * dp[i][j] = number of ways s[0..i-1] contains t[0..j-1] as a subsequence.
 * dp[i][0] = 1; dp[0][j>0] = 0.
 * If s[i-1]==t[j-1]: dp[i][j] = dp[i-1][j-1] + dp[i-1][j]
 * else:              dp[i][j] = dp[i-1][j]
 * g_result encodes (n_tests, sum_counts, xor_counts). */

static int slen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

static int count_subseq(const char *s, const char *t) {
    int m = slen(s);
    int n = slen(t);
    int dp[8][7];
    int i, j;
    for (i = 0; i <= m; i++) dp[i][0] = 1;
    for (j = 1; j <= n; j++) dp[0][j] = 0;
    for (i = 1; i <= m; i++)
        for (j = 1; j <= n; j++)
            dp[i][j] = (s[i - 1] == t[j - 1]) ?
                        dp[i - 1][j - 1] + dp[i - 1][j] :
                        dp[i - 1][j];
    return dp[m][n];
}

volatile uint32_t g_result;

void test_distinct_subseq(void) {
    int r1 = count_subseq("rabbbit", "rabbit"); /* 3 */
    int r2 = count_subseq("babgbag", "bag");    /* 5 */
    int r3 = count_subseq("aaa",     "a");      /* 3 */
    int s = r1 + r2 + r3;  /* 11 */
    int x = r1 ^ r2 ^ r3;  /* 5  */
    g_result = (3u << 16) | ((uint32_t)s << 8) | (uint32_t)x; /* 0x00030B05 */
}

__attribute__((noreturn)) void _start(void) {
    test_distinct_subseq();
    for (;;);
}
