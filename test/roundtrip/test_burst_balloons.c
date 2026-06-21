#include <stdint.h>

/* Burst balloons interval DP with sentinels.
 * Add sentinel 1 at both ends: b={1,nums[0],...,nums[n-1],1}.
 * dp[i][j] = max coins bursting all balloons strictly between i and j,
 *            where k is the LAST balloon burst in that range.
 * dp[i][j] = max_k(dp[i][k]+dp[k][j]+b[i]*b[k]*b[j]) for k in (i,j).
 * g_result encodes (n_balloons, max_coins&0xFF, dp[0][2]&0xFF). */

static int imax(int a, int b) { return a > b ? a : b; }

volatile uint32_t g_result;

void test_burst_balloons(void) {
    int nums[] = {3, 1, 5, 8};
    int n = 4;
    /* b[0..n+1] with sentinels */
    int b[6];
    int dp[6][6];
    int i, j, k, len;
    b[0] = 1; b[n + 1] = 1;
    for (i = 0; i < n; i++) b[i + 1] = nums[i];
    /* zero-init dp */
    for (i = 0; i < 6; i++)
        for (j = 0; j < 6; j++)
            dp[i][j] = 0;
    /* N = n+2 = 6 (indices 0..5 including sentinels) */
    for (len = 2; len < 6; len++) {
        for (i = 0; i < 6 - len; i++) {
            j = i + len;
            for (k = i + 1; k < j; k++) {
                int coins = dp[i][k] + dp[k][j] + b[i] * b[k] * b[j];
                dp[i][j] = imax(dp[i][j], coins);
            }
        }
    }
    /* dp[0][5]=167, dp[0][2]=3 */
    g_result = ((uint32_t)n << 16) |
               (((uint32_t)dp[0][5] & 0xFFu) << 8) |
               ((uint32_t)dp[0][2] & 0xFFu); /* 0x0004A703 */
}

__attribute__((noreturn)) void _start(void) {
    test_burst_balloons();
    for (;;);
}
