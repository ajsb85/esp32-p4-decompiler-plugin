/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — String Period via KMP Failure Function fixture.
 *
 * The smallest period p of a string s of length n is:
 *   p = n - fail[n-1]
 * where fail[] is the KMP prefix-failure function.
 * (Period iff n % p == 0, otherwise the string is aperiodic.)
 *
 * The failure function (partial match table) is built as:
 *   fail[0] = 0
 *   for i in 1..n-1:
 *     while j > 0 && s[j] != s[i]: j = fail[j-1]
 *     if s[j] == s[i]: j++
 *     fail[i] = j
 *
 * Distinctive decompiler idioms:
 *   1. `while (j > 0 && s[j] != s[i]) j = fail[j-1]` — KMP back-tracking
 *   2. `if (s[j] == s[i]) j++` — extend match
 *   3. `period = n - fail[n-1]` — period from failure function tail
 *   4. `n % period == 0` — exact period check
 *
 * Test strings:
 *   "abab"     → fail={0,0,1,2} → period = 4-2 = 2  → exact (4%2=0) ✓
 *   "abcabcabc"→ fail={0,0,0,1,2,3,4,5,6} → period = 9-6 = 3 → exact ✓
 *   "abaab"    → fail={0,0,1,1,2} → period = 5-2 = 3 → not exact (5%3≠0)
 *
 * Results:
 *   period_sum    = 2 + 3 + 3 = 8   (8 = 0x08)
 *   exact_count   = 2               (2 strings with exact period)
 *   n_tests       = 3
 *
 * g_result = (n_tests << 16) | (period_sum << 8) | exact_count = 0x00030802
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SP_MAXLEN 16

static int sp_fail[SP_MAXLEN];

static int string_len(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* Computes KMP failure function in sp_fail[]. Returns n. */
static int build_fail(const char *s)
{
    int n = string_len(s);
    sp_fail[0] = 0;
    for (int i = 1, j = 0; i < n; i++) {
        while (j > 0 && s[j] != s[i])
            j = sp_fail[j - 1];
        if (s[j] == s[i]) j++;
        sp_fail[i] = j;
    }
    return n;
}

/* Returns shortest period and writes 1 to *exact if n % period == 0. */
static int find_period(const char *s, int *exact)
{
    int n = build_fail(s);
    int period = n - sp_fail[n - 1];
    *exact = (n % period == 0) ? 1 : 0;
    return period;
}

void test_string_period(void)
{
    static const char s0[] = "abab";
    static const char s1[] = "abcabcabc";
    static const char s2[] = "abaab";

    int exact, period_sum = 0, exact_count = 0;

    period_sum  += find_period(s0, &exact); exact_count += exact;  /* 2, exact */
    period_sum  += find_period(s1, &exact); exact_count += exact;  /* 3, exact */
    period_sum  += find_period(s2, &exact); exact_count += exact;  /* 3, not */

    /* period_sum=8, exact_count=2 */
    g_result = (3u << 16)
             | ((uint32_t)period_sum  << 8)
             | ((uint32_t)exact_count & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_string_period();
    for (;;);
}
