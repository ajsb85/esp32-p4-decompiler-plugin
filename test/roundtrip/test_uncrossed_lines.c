#include <stdint.h>

/* Uncrossed Lines: max non-crossing connections between nums1 and nums2,
 * equivalent to LCS of the two integer arrays.
 * dp[i][j] = LCS length of a[0..i-1] and b[0..j-1].
 * g_result encodes (n_tests, max_lcs, n_nonzero_results). */

static int imax(int a, int b) { return a > b ? a : b; }

static int uncrossed(const int *a, int m, const int *b, int n) {
    int dp[6][7];
    int i, j;
    for (i = 0; i <= m; i++) dp[i][0] = 0;
    for (j = 0; j <= n; j++) dp[0][j] = 0;
    for (i = 1; i <= m; i++)
        for (j = 1; j <= n; j++)
            dp[i][j] = (a[i - 1] == b[j - 1]) ?
                        dp[i - 1][j - 1] + 1 :
                        imax(dp[i - 1][j], dp[i][j - 1]);
    return dp[m][n];
}

volatile uint32_t g_result;

void test_uncrossed_lines(void) {
    const int a1[] = {1,4,2},     b1[] = {1,2,4};        /* 2 */
    const int a2[] = {2,5,1,2,5}, b2[] = {10,5,2,1,5,2}; /* 3 */
    const int a3[] = {1,2,3},     b3[] = {4,5,6};         /* 0 */
    int r1 = uncrossed(a1, 3, b1, 3);
    int r2 = uncrossed(a2, 5, b2, 6);
    int r3 = uncrossed(a3, 3, b3, 3);
    int mx = r1 > r2 ? r1 : r2;                   /* max lcs = 3 */
    int nz = (r1 > 0) + (r2 > 0) + (r3 > 0);     /* nonzero count = 2 */
    g_result = (3u << 16) | ((uint32_t)mx << 8) | (uint32_t)nz; /* 0x00030302 */
}

__attribute__((noreturn)) void _start(void) {
    test_uncrossed_lines();
    for (;;);
}
