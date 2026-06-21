/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Manacher's palindrome algorithm round-trip fixture.
 *
 * Manacher's algorithm finds palindrome radii for every center in O(n) by
 * maintaining a [c, r) mirror window to reuse previously computed radii.
 *
 * Operates on a transformed string T where '#' separates characters, so that
 * both even and odd palindromes are handled uniformly:
 *
 *   original: "ABACABA"  (n=7)
 *   transformed T: "#A#B#A#C#A#B#A#"  (len=15)
 *
 * Algorithm idioms (decompiler-visible):
 *   mirror = 2*c - i                          ← mirror index
 *   if (i < r) p[i] = min(r-i, p[mirror]);   ← window initialisation
 *   while T[i-p[i]-1] == T[i+p[i]+1]: p[i]++ ← centre expansion
 *   if i+p[i] > r: c=i; r=i+p[i];            ← window advance
 *
 * P array (radius per position in T):
 *   {0,1,0,3,0,1,0,7,0,1,0,3,0,1,0}
 *
 * Longest palindrome: P[7]=7 ← "ABACABA" (entire string)
 *   max_p  = 7
 *   sum_p  = 17 = 0x11
 *   n_orig = 7
 *
 * g_result = (n_orig << 16) | (max_p << 8) | (sum_p & 0xFF) = 0x00070711
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Manacher ─────────────────────────────────────────────────────────────── */

#define MAN_N  15    /* length of transformed string */
#define MAN_OR  7    /* length of original string    */

static int man_p[MAN_N];

static void manacher(const char *t, int n, int *p)
{
    int c = 0, r = 0;
    for (int i = 0; i < n; i++) {
        int mirror = 2 * c - i;
        if (i < r)
            p[i] = (r - i < p[mirror]) ? r - i : p[mirror];
        else
            p[i] = 0;
        /* expand around centre i */
        while (i - p[i] - 1 >= 0 && i + p[i] + 1 < n
               && t[i - p[i] - 1] == t[i + p[i] + 1])
            p[i]++;
        if (i + p[i] > r) {
            c = i;
            r = i + p[i];
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_manacher(void)
{
    /* Transformed "ABACABA": sentinel '#' between every character */
    static const char t[MAN_N + 1] = "#A#B#A#C#A#B#A#";

    manacher(t, MAN_N, man_p);
    /* man_p = {0,1,0,3,0,1,0,7,0,1,0,3,0,1,0} */

    uint32_t sum_p = 0, max_p = 0;
    for (int i = 0; i < MAN_N; i++) {
        sum_p += (uint32_t)man_p[i];
        if ((uint32_t)man_p[i] > max_p)
            max_p = (uint32_t)man_p[i];
    }

    g_result = ((uint32_t)MAN_OR << 16)
             | (max_p << 8)
             | (sum_p & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_manacher();
    for (;;);
}
