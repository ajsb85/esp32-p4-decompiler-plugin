/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Minimum Palindrome Cuts (interval DP) fixture.
 *
 * Find the minimum number of cuts to partition a string into palindromes.
 *
 * Two-phase interval DP:
 *   Phase 1 – precompute is_pal[i][j]:
 *     is_pal[i][i]   = 1          (single char)
 *     is_pal[i][i+1] = (s[i]==s[i+1])
 *     is_pal[i][j]   = s[i]==s[j] && is_pal[i+1][j-1]
 *
 *   Phase 2 – DP on minimum cuts:
 *     dp[i] = 0                     if is_pal[0][i]  (whole prefix is palindrome)
 *     dp[i] = min{ dp[j-1]+1 }      for j∈[1..i] where is_pal[j][i]
 *
 * Distinctive decompiler idioms:
 *   1. `is_pal[i][j] = s[i]==s[j] && (j-i<2 || is_pal[i+1][j-1])` — expand-from-ends
 *   2. `if (is_pal[0][i]) dp[i]=0` — whole-prefix palindrome short-circuit
 *   3. `dp[i] = min(dp[j-1]+1)` for is_pal[j][i]
 *
 * Test strings:
 *   "aab"    → 1  (aa | b)
 *   "abcba"  → 0  (whole string is palindrome)
 *   "aabbc"  → 2  (aa | bb | c)
 *
 * n_tests = 3
 * sum     = 1+0+2 = 3
 * xor     = 1^0^2 = 3
 *
 * g_result = (n_tests << 16) | (sum << 8) | xor = 0x00030303
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── String length (bare metal, no stdlib) ───────────────────────────────────── */

static int pp_strlen(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* ── Minimum palindrome cuts ─────────────────────────────────────────────────── */

#define PP_MAXN 16

static int pp_pal[PP_MAXN][PP_MAXN];
static int pp_dp[PP_MAXN];

static int min_pal_cuts(const char *s)
{
    int n = pp_strlen(s);

    /* clear palindrome table */
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            pp_pal[i][j] = 0;

    /* base cases */
    for (int i = 0; i < n; i++) pp_pal[i][i] = 1;
    for (int i = 0; i < n - 1; i++)
        if (s[i] == s[i + 1]) pp_pal[i][i + 1] = 1;

    /* fill for lengths 3..n */
    for (int len = 3; len <= n; len++) {
        for (int i = 0; i <= n - len; i++) {
            int j = i + len - 1;
            if (s[i] == s[j] && pp_pal[i + 1][j - 1])
                pp_pal[i][j] = 1;
        }
    }

    /* DP for minimum cuts */
    for (int i = 0; i < n; i++) pp_dp[i] = i; /* worst case: i cuts */
    if (pp_pal[0][n - 1]) return 0;
    for (int i = 1; i < n; i++) {
        if (pp_pal[0][i]) { pp_dp[i] = 0; continue; }
        for (int j = 1; j <= i; j++) {
            if (pp_pal[j][i] && pp_dp[j - 1] + 1 < pp_dp[i])
                pp_dp[i] = pp_dp[j - 1] + 1;
        }
    }
    return pp_dp[n - 1];
}

/* ── Test entry point ────────────────────────────────────────────────────────── */

void test_palindrome_partition(void)
{
    static const char s1[] = "aab";
    static const char s2[] = "abcba";
    static const char s3[] = "aabbc";

    uint32_t sum = 0, xor_val = 0;
    uint32_t c;

    c = (uint32_t)min_pal_cuts(s1); sum += c; xor_val ^= c; /* 1 */
    c = (uint32_t)min_pal_cuts(s2); sum += c; xor_val ^= c; /* 0 */
    c = (uint32_t)min_pal_cuts(s3); sum += c; xor_val ^= c; /* 2 */
    /* sum=3, xor=3 */
    g_result = (3u << 16) | (sum << 8) | (xor_val & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_palindrome_partition();
    for (;;);
}
