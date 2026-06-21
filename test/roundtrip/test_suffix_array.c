/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Suffix Array (insertion-sort construction) fixture.
 *
 * Builds a suffix array for the string "banana" by insertion-sorting suffix
 * start indices by lexicographic suffix order.
 *
 * Distinctive decompiler idioms:
 *   1. `sa[i] = i` — initialise index array
 *   2. Insertion sort with `strcmp(s+sa[j], s+key) > 0` comparator
 *   3. SA[0] = index of lexicographically smallest suffix ("a" at index 5)
 *   4. XOR all SA entries to produce a compact result
 *
 * String: "banana" (n=6)
 * Suffixes sorted: "a"(5), "ana"(3), "anana"(1), "banana"(0), "na"(4), "nana"(2)
 * SA = {5, 3, 1, 0, 4, 2}
 *
 * n         = 6
 * SA[0]     = 5   (smallest suffix starts at index 5)
 * xor_SA    = 5^3^1^0^4^2 = 1
 *
 * g_result = (n << 16) | (SA[0] << 8) | xor_SA = 0x00060501
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SA_N 6
static const char sa_str[SA_N + 1] = "banana";
static int sa_idx[SA_N];

/* character-by-character suffix comparison (no stdlib) */
static int sa_cmp_suffix(int a, int b)
{
    const char *pa = sa_str + a, *pb = sa_str + b;
    while (*pa && *pa == *pb) { pa++; pb++; }
    return (int)(unsigned char)*pa - (int)(unsigned char)*pb;
}

void test_suffix_array(void)
{
    for (int i = 0; i < SA_N; i++) sa_idx[i] = i;

    /* insertion sort by suffix order */
    for (int i = 1; i < SA_N; i++) {
        int key = sa_idx[i], j = i - 1;
        while (j >= 0 && sa_cmp_suffix(sa_idx[j], key) > 0) {
            sa_idx[j + 1] = sa_idx[j];
            j--;
        }
        sa_idx[j + 1] = key;
    }

    uint32_t first_sa = (uint32_t)sa_idx[0];
    uint32_t xor_sa   = 0;
    for (int i = 0; i < SA_N; i++)
        xor_sa ^= (uint32_t)sa_idx[i];

    /* first_sa=5, xor_sa=1 */
    g_result = ((uint32_t)SA_N << 16) | (first_sa << 8) | (xor_sa & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_suffix_array();
    for (;;);
}
