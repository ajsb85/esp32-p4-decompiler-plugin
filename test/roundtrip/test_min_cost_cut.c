#include <stdint.h>

/* Minimum cost to cut a stick at given positions (interval DP).
 * Augment cuts[] with endpoints 0 and len, sort, then:
 * dp[i][j] = min cost to perform all cuts between arr[i] and arr[j].
 * dp[i][j] = min_k(dp[i][k] + dp[k][j] + arr[j] - arr[i]) for k in (i,j).
 * g_result encodes (n_cuts, stick_len, min_cost&0xFF). */

#define INF 0x7fffffff

static int min_cut_cost(int len, const int *cuts, int nc) {
    int arr[8];
    int m = nc + 2;
    int dp[8][8];
    int i, j, k, gap;
    arr[0] = 0;
    for (i = 0; i < nc; i++) arr[i + 1] = cuts[i];
    arr[nc + 1] = len;
    /* insertion sort */
    for (i = 1; i < m; i++) {
        int key = arr[i];
        j = i - 1;
        while (j >= 0 && arr[j] > key) { arr[j + 1] = arr[j]; j--; }
        arr[j + 1] = key;
    }
    for (i = 0; i < m; i++)
        for (j = 0; j < m; j++)
            dp[i][j] = 0;
    for (gap = 2; gap < m; gap++) {
        for (i = 0; i + gap < m; i++) {
            j = i + gap;
            dp[i][j] = INF;
            for (k = i + 1; k < j; k++) {
                int cost = dp[i][k] + dp[k][j] + arr[j] - arr[i];
                if (cost < dp[i][j]) dp[i][j] = cost;
            }
        }
    }
    return dp[0][m - 1];
}

volatile uint32_t g_result;

void test_min_cost_cut(void) {
    const int cuts[] = {1, 3, 4, 5};
    int nc = 4, len = 7;
    int mc = min_cut_cost(len, cuts, nc); /* 16 */
    g_result = ((uint32_t)nc << 16) |
               ((uint32_t)len << 8) |
               ((uint32_t)mc & 0xFFu); /* 0x00040710 */
}

__attribute__((noreturn)) void _start(void) {
    test_min_cost_cut();
    for (;;);
}
