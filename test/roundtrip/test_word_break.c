/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Word Break DP fixture.
 *
 * Tests whether a string can be segmented into words from a dictionary.
 * Classic bottom-up DP: dp[i] = "s[0..i-1] can be broken by dict words."
 *
 * Distinctive decompiler idioms:
 *   1. `dp[0] = 1` (empty prefix always valid) — single non-zero seed
 *   2. `if (dp[i-wlen] && strncmp(s+i-wlen, word, wlen)==0) dp[i]=1`
 *      — sliding window + backward dp access at offset -wlen
 *   3. Outer loop over position i, inner loop over dictionary words
 *   4. `return dp[slen]` — final cell is the answer
 *
 * Three test cases:
 *   1. s="leetcode",     dict={"leet","code"}                  → YES (1)
 *   2. s="applepenapple",dict={"apple","pen"}                  → YES (1)
 *   3. s="catsandog",    dict={"cats","dog","and","cat","sand"} → NO  (0)
 *
 * n_tests   = 3
 * count_yes = 2   (tests 1 and 2)
 * xor_val   = (len1^r1) ^ (len2^r2) ^ (len3^r3)
 *           = (8^1) ^ (13^1) ^ (9^0) = 9 ^ 12 ^ 9 = 12
 *
 * g_result = (n_tests << 16) | (count_yes << 8) | xor_val = 0x0003020C
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int wb_strncmp(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i]) return 1;
    }
    return 0;
}

static int wb_strlen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* ── Word Break DP ───────────────────────────────────────────────────────── */

#define WB_MAXS  20
#define WB_MAXD  5
#define WB_WL    10

static int wb_dp[WB_MAXS + 1];

static int word_break(const char *s, int slen,
                      const char dict[][WB_WL], int ndict)
{
    for (int i = 0; i <= slen; i++) wb_dp[i] = 0;
    wb_dp[0] = 1;
    for (int i = 1; i <= slen; i++) {
        for (int d = 0; d < ndict; d++) {
            int wlen = wb_strlen(dict[d]);
            if (i >= wlen && wb_dp[i - wlen]) {
                if (wb_strncmp(s + i - wlen, dict[d], wlen) == 0) {
                    wb_dp[i] = 1;
                    break;
                }
            }
        }
    }
    return wb_dp[slen];
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_word_break(void)
{
    static const char s1[] = "leetcode";
    static const char d1[2][WB_WL] = {"leet", "code"};

    static const char s2[] = "applepenapple";
    static const char d2[2][WB_WL] = {"apple", "pen"};

    static const char s3[] = "catsandog";
    static const char d3[5][WB_WL] = {"cats", "dog", "and", "cat", "sand"};

    int r1 = word_break(s1, wb_strlen(s1), d1, 2);  /* 1 */
    int r2 = word_break(s2, wb_strlen(s2), d2, 2);  /* 1 */
    int r3 = word_break(s3, wb_strlen(s3), d3, 5);  /* 0 */

    uint32_t count_yes = (uint32_t)(r1 + r2 + r3);
    /* xor_val = (8^1) ^ (13^1) ^ (9^0) = 9^12^9 = 12 */
    uint32_t xor_val = (uint32_t)(
        (wb_strlen(s1) ^ r1) ^ (wb_strlen(s2) ^ r2) ^ (wb_strlen(s3) ^ r3));

    g_result = (3u << 16) | (count_yes << 8) | (xor_val & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_word_break();
    for (;;);
}
