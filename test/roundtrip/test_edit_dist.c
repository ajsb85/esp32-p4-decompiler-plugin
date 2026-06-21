/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Levenshtein edit distance (2D DP) round-trip fixture.
 *
 * Bottom-up dynamic programming for edit distance.  At each cell dp[i][j]:
 *   - If s1[i-1] == s2[j-1]: dp[i][j] = dp[i-1][j-1]  (no cost)
 *   - Else: dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
 *             (delete, insert, substitute)
 *
 * Inputs:
 *   s1 = "KITTEN"  (len = 6)
 *   s2 = "SITTING" (len = 7)
 *
 * Edit distance = 3 (K→S substitute, E→I substitute, insert G at end).
 *
 * g_result = (la << 16) | (lb << 8) | dist = 0x00060703
 *
 * Recognizable decompiler idioms:
 *   if (s1[i-1] == s2[j-1]) dp[i][j] = dp[i-1][j-1];  ← match diagonal
 *   else dp[i][j] = 1 + min3(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);  ← 3-way min
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── 2D DP edit distance ──────────────────────────────────────────────────── */

static int dp_ed[7][8];   /* [0..la][0..lb] */

static int min3(int a, int b, int c)
{
    int ab = a < b ? a : b;
    return ab < c ? ab : c;
}

static int edit_dist(const char *s1, int la, const char *s2, int lb)
{
    for (int i = 0; i <= la; i++) dp_ed[i][0] = i;
    for (int j = 0; j <= lb; j++) dp_ed[0][j] = j;

    for (int i = 1; i <= la; i++) {
        for (int j = 1; j <= lb; j++) {
            if (s1[i - 1] == s2[j - 1]) {
                dp_ed[i][j] = dp_ed[i - 1][j - 1];
            } else {
                dp_ed[i][j] = 1 + min3(dp_ed[i - 1][j],
                                        dp_ed[i][j - 1],
                                        dp_ed[i - 1][j - 1]);
            }
        }
    }
    return dp_ed[la][lb];
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_edit_dist(void)
{
    static const char s1[7] = "KITTEN";   /* len 6 */
    static const char s2[8] = "SITTING";  /* len 7 */
    const int la = 6, lb = 7;

    int dist = edit_dist(s1, la, s2, lb);  /* = 3 */

    g_result = ((uint32_t)la << 16)
             | ((uint32_t)lb << 8)
             | ((uint32_t)dist & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_edit_dist();
    for (;;);
}
