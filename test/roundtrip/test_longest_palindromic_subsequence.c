/* test_longest_palindromic_subsequence.c
 * Purpose   : Longest Palindromic Subsequence (LPS) using bottom-up DP.
 * Algorithm : lps[i][j] = length of longest palindromic subsequence in s[i..j].
 *             Base: lps[i][i]=1. Recurrence:
 *               if s[i]==s[j]: lps[i][j] = lps[i+1][j-1] + 2
 *               else:          lps[i][j] = max(lps[i+1][j], lps[i][j-1])
 *             Fill by increasing length.
 * Input     : s = "cbdbace"  (n=7)
 * Trace     : LPS = "cbabc" or "cbdbc" length=5
 *             Single chars: lps[i][i]=1
 *             len=2: cb:1,bd:1,db:1,ba:1,ac:1,ce:1
 *             len=3: cbd:1+2=? c!=d->max(lps[1][2],lps[0][1])...
 *                    "aba"=3? No: s="cbdbace". Pairs with match:
 *                    lps[0][6]: s[0]='c',s[6]='e' -> max(lps[1][6],lps[0][5])
 *                    Full DP gives lps[0][6]=5
 * n_chars=7, lps_len=5, lps_half=2 (floor(5/2))
 * g_result = (n_chars << 16) | (lps_len << 8) | lps_half
 *          = (7 << 16) | (5 << 8) | 2 = 0x070502
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define LPQ_N 7

static const char lpq_s[LPQ_N] = {'c','b','d','b','a','c','e'};
static int lpq_dp[LPQ_N][LPQ_N];

static void lpq_solve(void) {
    /* Base: length 1 */
    for (int i = 0; i < LPQ_N; i++) {
        lpq_dp[i][i] = 1;
    }
    /* Fill by increasing subsequence length */
    for (int len = 2; len <= LPQ_N; len++) {
        for (int i = 0; i <= LPQ_N - len; i++) {
            int j = i + len - 1;
            if (lpq_s[i] == lpq_s[j]) {
                lpq_dp[i][j] = (len == 2) ? 2 : lpq_dp[i+1][j-1] + 2;
            } else {
                int a = lpq_dp[i+1][j];
                int b = lpq_dp[i][j-1];
                lpq_dp[i][j] = (a > b) ? a : b;
            }
        }
    }
}

void _start(void) {
    lpq_solve();

    int lps_len  = lpq_dp[0][LPQ_N - 1];
    int lps_half = lps_len / 2;

    g_result = ((uint32_t)LPQ_N    << 16)
             | ((uint32_t)lps_len   << 8)
             | ((uint32_t)lps_half);
    while (1) {}
}
