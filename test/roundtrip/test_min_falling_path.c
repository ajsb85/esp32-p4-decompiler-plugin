#include <stdint.h>

/* Minimum falling path sum in an n×n grid.
 * Each step moves to the same or adjacent column in the next row.
 * dp[i][j] = min of (dp[i-1][j-1], dp[i-1][j], dp[i-1][j+1]) + grid[i][j].
 * g_result encodes (n, min_path, sum_of_last_dp_row). */

volatile uint32_t g_result;

void test_min_falling_path(void) {
    int n = 3;
    int grid[3][3] = {{2,1,3},{6,5,4},{7,8,9}};
    int dp[3][3];

    for (int j = 0; j < n; j++) dp[0][j] = grid[0][j];

    for (int i = 1; i < n; i++) {
        for (int j = 0; j < n; j++) {
            int mn = dp[i-1][j];
            if (j > 0   && dp[i-1][j-1] < mn) mn = dp[i-1][j-1];
            if (j < n-1 && dp[i-1][j+1] < mn) mn = dp[i-1][j+1];
            dp[i][j] = mn + grid[i][j];
        }
    }

    int ans = dp[n-1][0], row_sum = 0;
    for (int j = 0; j < n; j++) {
        if (dp[n-1][j] < ans) ans = dp[n-1][j];
        row_sum += dp[n-1][j];
    }
    /* ans=13, row_sum=40 → g=0x00030D28 */
    g_result = ((uint32_t)n << 16) | ((uint32_t)ans << 8) | (uint32_t)row_sum;
}

__attribute__((noreturn)) void _start(void) {
    test_min_falling_path();
    for (;;);
}
