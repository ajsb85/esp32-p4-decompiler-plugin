#include <stdint.h>

/* Stone Game: two optimal players alternately take from either end of array.
 * dp[i][j] = score difference (current player minus opponent) for a[i..j].
 * dp[i][i] = a[i]; dp[i][j] = max(a[i]-dp[i+1][j], a[j]-dp[i][j-1]).
 * g_result encodes (n_tests, sum_diffs, xor_diffs) for 3 test arrays. */

static int stone_game(const int *a, int n) {
    int dp[4][4];
    int i, j, len;
    for (i = 0; i < n; i++)
        for (j = 0; j < n; j++)
            dp[i][j] = 0;
    for (i = 0; i < n; i++) dp[i][i] = a[i];
    for (len = 2; len <= n; len++) {
        for (i = 0; i + len - 1 < n; i++) {
            int x, y;
            j = i + len - 1;
            x = a[i] - dp[i + 1][j];
            y = a[j] - dp[i][j - 1];
            dp[i][j] = x > y ? x : y;
        }
    }
    return dp[0][n - 1];
}

volatile uint32_t g_result;

void test_stone_game(void) {
    const int a1[] = {5, 3, 4, 5};    /* diff = 1  */
    const int a2[] = {3, 4, 2, 1};    /* diff = 0  */
    const int a3[] = {1, 5, 233, 7};  /* diff = 222 */
    int r1 = stone_game(a1, 4);
    int r2 = stone_game(a2, 4);
    int r3 = stone_game(a3, 4);
    int s = r1 + r2 + r3;  /* 223 */
    int x = r1 ^ r2 ^ r3;  /* 223 */
    g_result = (3u << 16) | ((uint32_t)s << 8) | (uint32_t)x; /* 0x0003DFDF */
}

__attribute__((noreturn)) void _start(void) {
    test_stone_game();
    for (;;);
}
