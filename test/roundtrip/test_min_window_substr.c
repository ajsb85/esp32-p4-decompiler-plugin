/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Minimum Window Substring (sliding window) fixture.
 *
 * Finds the minimum-length window in s that contains all chars of t.
 * Two-pointer approach: expand right until all required chars present, then
 * shrink left while still satisfying. Track minimum window size.
 *
 * Distinctive decompiler idioms:
 *   1. `cnt_s[s[right]]++; if (cnt_s[s[right]] == cnt_t[s[right]]) formed++`
 *   2. `while (formed == required) { ... cnt_s[s[left]]--; ... left++ }`
 *   3. `if (right - left + 1 < min_len) min_len = right - left + 1`
 *
 * Test cases:
 *   "ADOBECODEBANC" / "ABC" → window "BANC", len=4
 *   "a" / "a"              → window "a",    len=1
 *   "AABBBBC" / "AABC"     → window "AABBBBC", len=7
 *   n_tests=3, sum=4+1+7=12=0x0C, xor=4^1^7=2=0x02
 *
 * g_result = (3 << 16) | (12 << 8) | 2 = 0x00030C02
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MW_ALPHA 128

static int mw_cnt_s[MW_ALPHA];
static int mw_cnt_t[MW_ALPHA];

static int min_window(const char *s, int ns, const char *t, int nt)
{
    for (int i = 0; i < MW_ALPHA; i++) { mw_cnt_s[i] = 0; mw_cnt_t[i] = 0; }
    for (int i = 0; i < nt; i++) mw_cnt_t[(unsigned char)t[i]]++;

    int required = 0;
    for (int i = 0; i < MW_ALPHA; i++) if (mw_cnt_t[i] > 0) required++;

    int formed = 0, left = 0, min_len = ns + 1;
    for (int right = 0; right < ns; right++) {
        int c = (unsigned char)s[right];
        mw_cnt_s[c]++;
        if (mw_cnt_t[c] > 0 && mw_cnt_s[c] == mw_cnt_t[c]) formed++;
        while (formed == required) {
            if (right - left + 1 < min_len) min_len = right - left + 1;
            int lc = (unsigned char)s[left];
            mw_cnt_s[lc]--;
            if (mw_cnt_t[lc] > 0 && mw_cnt_s[lc] < mw_cnt_t[lc]) formed--;
            left++;
        }
    }
    return min_len > ns ? 0 : min_len;
}

void test_min_window_substr(void)
{
    int r0 = min_window("ADOBECODEBANC", 13, "ABC",  3); /* 4 */
    int r1 = min_window("a",              1, "a",    1); /* 1 */
    int r2 = min_window("AABBBBC",        7, "AABC", 4); /* 7 */

    g_result = (3u << 16)
             | ((uint32_t)((r0 + r1 + r2) & 0xFF) << 8)
             | ((uint32_t)((r0 ^ r1 ^ r2) & 0xFF));
}

__attribute__((noreturn)) void _start(void)
{
    test_min_window_substr();
    for (;;);
}
