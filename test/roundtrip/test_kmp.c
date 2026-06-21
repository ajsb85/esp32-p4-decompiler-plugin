/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Knuth-Morris-Pratt (KMP) string search fixture.
 *
 * KMP linear-time string pattern matching.  Two recognizable decompiler
 * idioms (generated as two separate functions):
 *
 *  1. Failure function (prefix table):
 *       for i in [1, m): while k>0 && pat[k]!=pat[i]: k=fail[k-1]
 *                         if pat[k]==pat[i]: k++
 *                         fail[i] = k
 *
 *  2. KMP search:
 *       while k>0 && text[i]!=pat[k]: k=fail[k-1]
 *       if text[i]==pat[k]: k++
 *       if k==m: match found at i-m+1
 *
 * Inputs:
 *   text    = "ABABABABC"  (len=9)
 *   pattern = "ABABC"      (len=5)
 *
 * Failure function for "ABABC": [0, 0, 1, 2, 0]
 *
 * KMP match trace:
 *   pos 0-3: "ABAB" matched → kk=4
 *   pos 4: 'A' vs 'C' → mismatch; kk=fail[3]=2; 'A'=pat[2] → kk=3
 *   pos 5-6: "BA" → kk=4 then 'A' vs 'C' → kk=2 → 'A'=pat[2] → kk=3
 *   pos 7-8: "BC" → kk=4, kk=5 → match at pos 8-5+1=4
 *
 * First match position = 4 (0-indexed).
 *
 * g_result = (text_len << 16) | (pattern_len << 8) | match_pos
 *           = (9 << 16) | (5 << 8) | 4 = 0x00090504
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Failure / prefix function ───────────────────────────────────────────── */

static void kmp_failure(const char *pat, int m, int *fail)
{
    fail[0] = 0;
    int k = 0;
    for (int i = 1; i < m; i++) {
        while (k > 0 && pat[k] != pat[i])
            k = fail[k - 1];
        if (pat[k] == pat[i])
            k++;
        fail[i] = k;
    }
}

/* ── KMP search — returns index of first match, or -1 ───────────────────── */

static int kmp_search(const char *text, int n,
                      const char *pat,  int m,
                      const int  *fail)
{
    int k = 0;
    for (int i = 0; i < n; i++) {
        while (k > 0 && text[i] != pat[k])
            k = fail[k - 1];
        if (text[i] == pat[k])
            k++;
        if (k == m)
            return i - m + 1;
    }
    return -1;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_kmp(void)
{
    static const char text[10] = "ABABABABC"; /* len 9 */
    static const char pat[6]   = "ABABC";     /* len 5 */

    int fail[5];
    kmp_failure(pat, 5, fail);

    int pos = kmp_search(text, 9, pat, 5, fail);

    g_result = (9u << 16)
             | (5u << 8)
             | ((uint32_t)(pos >= 0 ? pos : 0xFF) & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_kmp();
    for (;;);
}
