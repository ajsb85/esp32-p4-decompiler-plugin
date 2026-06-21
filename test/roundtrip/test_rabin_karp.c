/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Rabin-Karp Rolling Hash String Search fixture.
 *
 * Searches for all occurrences of a pattern in text using a rolling hash:
 *
 *   hash = (hash * BASE + char) % MOD    (extend window)
 *   hash = (hash - oldest_char * h_pow + MOD*h_pow) * BASE + new_char) % MOD
 *
 * Distinctive decompiler idioms (vs naive O(n*m)):
 *   1. Separate initial hash construction + rolling-update loop
 *   2. `h_pow = BASE^(m-1) % MOD` computed once before the slide loop
 *   3. `((h + (MOD - leading) * h_pow) % MOD * BASE + trailing) % MOD` — remove-and-slide
 *   4. Character-level verification after hash match (handles collisions)
 *
 * Text:    "aaabaabaab" (n=10)
 * Pattern: "aab"        (m=3)
 * BASE=26 (letters a-z mapped to 0-25), MOD=101
 *
 * h_pow = 26^2 % 101 = 676 % 101 = 70
 * hash("aab") = (0*676 + 0*26 + 1) % 101 = 1
 *
 * Matches at: 1, 4, 7  (text[1..3]="aab", [4..6]="aab", [7..9]="aab")
 *
 * count   = 3
 * xor_pos = 1^4^7 = 2
 *
 * g_result = (n << 16) | (count << 8) | xor_pos = 0x000A0302
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Rabin-Karp ──────────────────────────────────────────────────────────── */

#define RK_N    10
#define RK_M    3
#define RK_BASE 26
#define RK_MOD  101

static const char rk_text[RK_N + 1] = "aaabaabaab";
static const char rk_pat[RK_M + 1]  = "aab";
static int rk_matches[RK_N];

static int rabin_karp(void)
{
    /* h_pow = BASE^(m-1) % MOD — needed to remove the leading character */
    int h_pow = 1;
    for (int i = 0; i < RK_M - 1; i++) h_pow = h_pow * RK_BASE % RK_MOD;

    /* hash(pattern) and hash(first window) */
    int h_pat = 0, h_txt = 0;
    for (int i = 0; i < RK_M; i++) {
        h_pat = (h_pat * RK_BASE + (rk_pat[i]  - 'a')) % RK_MOD;
        h_txt = (h_txt * RK_BASE + (rk_text[i] - 'a')) % RK_MOD;
    }

    int count = 0;
    for (int i = 0; i <= RK_N - RK_M; i++) {
        if (h_txt == h_pat) {
            /* verify to rule out hash collisions */
            int ok = 1;
            for (int j = 0; j < RK_M; j++)
                if (rk_text[i + j] != rk_pat[j]) { ok = 0; break; }
            if (ok) rk_matches[count++] = i;
        }
        if (i < RK_N - RK_M) {
            /* rolling: remove leading char, append trailing char */
            int lead = rk_text[i]       - 'a';
            int next = rk_text[i + RK_M] - 'a';
            h_txt = ((h_txt + (RK_MOD - lead) * h_pow) % RK_MOD * RK_BASE + next) % RK_MOD;
        }
    }
    return count;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_rabin_karp(void)
{
    int count = rabin_karp();
    uint32_t xor_pos = 0;
    for (int i = 0; i < count; i++) xor_pos ^= (uint32_t)rk_matches[i];
    /* count=3, xor_pos=1^4^7=2 */

    g_result = ((uint32_t)RK_N << 16) | ((uint32_t)count << 8) | (xor_pos & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_rabin_karp();
    for (;;);
}
