/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Common Prefix (vertical scan) fixture.
 *
 * Finds the longest common prefix of an array of strings via vertical scanning:
 * compare column by column, stop at first mismatch.
 *
 * Distinctive decompiler idioms:
 *   1. `while (a[i] && b[i] && a[i] == b[i]) i++` — pairwise LCP helper
 *   2. Reduce: `for (i=2; i<n; i++) if (lcp_len(s0,si) < len) len = ...` — fold
 *   3. n_tests=3, lcp_lens={2,0,5}, sum=7, last=5
 *
 * Test cases:
 *   {"flower","flow","flight"}       → "fl"  len=2
 *   {"dog","racecar","car"}          → ""    len=0
 *   {"interview","interstellar","internal"} → "inter" len=5
 *
 * g_result = (n_tests<<16) | (sum_lens<<8) | last_len = 0x00030705
 */
#include <stdint.h>

volatile uint32_t g_result;

static int lcp_two(const char *a, const char *b)
{
    int i = 0;
    while (a[i] && b[i] && a[i] == b[i]) i++;
    return i;
}

static int str_lcp(const char *strs[], int n)
{
    int len = lcp_two(strs[0], strs[1]);
    for (int i = 2; i < n; i++) {
        int l = lcp_two(strs[0], strs[i]);
        if (l < len) len = l;
    }
    return len;
}

void test_longest_common_prefix(void)
{
    const char *s1[] = {"flower", "flow", "flight"};
    const char *s2[] = {"dog", "racecar", "car"};
    const char *s3[] = {"interview", "interstellar", "internal"};

    int lens[3];
    lens[0] = str_lcp(s1, 3);
    lens[1] = str_lcp(s2, 3);
    lens[2] = str_lcp(s3, 3);

    uint32_t sum  = (uint32_t)(lens[0] + lens[1] + lens[2]);
    uint32_t last = (uint32_t)lens[2];
    /* sum=7=0x07, last=5=0x05 */
    g_result = (3u << 16) | (sum << 8) | last;
}

__attribute__((noreturn)) void _start(void)
{
    test_longest_common_prefix();
    for (;;);
}
