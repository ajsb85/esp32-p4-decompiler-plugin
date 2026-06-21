/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Levenshtein Edit Distance (2D DP).
 *
 * Computes minimum edit distance (insert/delete/substitute) between strings.
 * dp[i][j] = min edit dist between s1[0..i-1] and s2[0..j-1].
 *
 * Distinctive decompiler idioms:
 *   1. `dp[i][0]=i; dp[0][j]=j` — DP initialization (all insertions/deletions)
 *   2. `cost=(a[i-1]==b[j-1])?0:1` — substitution cost
 *   3. `mn=min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)` — recurrence
 *
 * Pairs: "kitten"→"sitting"=3, "saturday"→"sunday"=3, "intention"→"execution"=5
 * n_pairs=3, sum_dist=11, xor_dist=3^3^5=5
 *
 * g_result = (3<<16)|(sum<<8)|xor = 0x00030B05
 */
#include <stdint.h>

volatile uint32_t g_result;

static int dp_lev[10][10];

static int lev_dist(const char *a, int m, const char *b, int n)
{
    int i, j;
    for (i = 0; i <= m; i++) dp_lev[i][0] = i;
    for (j = 0; j <= n; j++) dp_lev[0][j] = j;
    for (i = 1; i <= m; i++) {
        for (j = 1; j <= n; j++) {
            int cost = (a[i-1] == b[j-1]) ? 0 : 1;
            int mn = dp_lev[i-1][j] + 1;
            if (dp_lev[i][j-1] + 1 < mn) mn = dp_lev[i][j-1] + 1;
            if (dp_lev[i-1][j-1] + cost < mn) mn = dp_lev[i-1][j-1] + cost;
            dp_lev[i][j] = mn;
        }
    }
    return dp_lev[m][n];
}

void test_levenshtein(void)
{
    static const char *a[3] = {"kitten", "saturday", "intention"};
    static const char *b[3] = {"sitting", "sunday", "execution"};
    static const int m[3] = {6, 8, 9};
    static const int n[3] = {7, 6, 9};
    int dist[3], i;

    for (i = 0; i < 3; i++) dist[i] = lev_dist(a[i], m[i], b[i], n[i]);

    /* dist={3,3,5}, sum=11, xor=5 */
    int sum = dist[0] + dist[1] + dist[2];
    int xr  = dist[0] ^ dist[1] ^ dist[2];
    g_result = (3u << 16)
             | ((uint32_t)sum << 8)
             | (uint32_t)xr;
}

__attribute__((noreturn)) void _start(void)
{
    test_levenshtein();
    for (;;);
}
