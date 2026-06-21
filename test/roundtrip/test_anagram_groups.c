/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Anagram Groups (frequency-vector matching).
 *
 * Groups words into anagram classes using character frequency comparison.
 * For each unmatched word, scans remaining words and groups matches.
 *
 * Distinctive decompiler idioms:
 *   1. `freq[*c-'a']++; freq[*c-'a']--` — encode first word, decode second
 *   2. `for(k<26) if(freq[k]!=0){is_ana=0;break}` — check zero residual
 *   3. Track group sizes; find max and XOR across groups
 *
 * Words: "eat","tea","tan","ate","nat","bat"
 * Groups: {eat,tea,ate}=3, {tan,nat}=2, {bat}=1 → n_groups=3
 * max_group=3, xor_sizes=3^2^1=0
 *
 * g_result = (n_groups<<16)|(max_group<<8)|(xor_sizes&0xFF) = 0x00030300
 */
#include <stdint.h>

volatile uint32_t g_result;

__attribute__((optimize("O1")))
void test_anagram_groups(void)
{
    static const char *words[6] = {"eat","tea","tan","ate","nat","bat"};
    int n = 6;
    int group_sizes[6] = {0};
    int matched[6]     = {0};
    int ng = 0;
    int freq[26];

    for (int i = 0; i < n; i++) {
        if (matched[i]) continue;
        int gsz = 1;
        matched[i] = 1;
        for (int j = i + 1; j < n; j++) {
            if (matched[j]) continue;
            int k;
            for (k = 0; k < 26; k++) freq[k] = 0;
            for (const char *c = words[i]; *c; c++) freq[*c - 'a']++;
            for (const char *c = words[j]; *c; c++) freq[*c - 'a']--;
            int is_ana = 1;
            for (k = 0; k < 26; k++) if (freq[k]) { is_ana = 0; break; }
            if (is_ana) { matched[j] = 1; gsz++; }
        }
        group_sizes[ng++] = gsz;
    }

    int maxg = 0;
    uint32_t xr = 0;
    for (int i = 0; i < ng; i++) {
        if (group_sizes[i] > maxg) maxg = group_sizes[i];
        xr ^= (uint32_t)group_sizes[i];
    }
    /* ng=3, maxg=3, xr=3^2^1=0 */
    g_result = ((uint32_t)ng << 16)
             | ((uint32_t)maxg << 8)
             | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_anagram_groups();
    for (;;);
}
