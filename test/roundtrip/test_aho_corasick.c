/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Aho-Corasick Multi-Pattern Search fixture.
 *
 * Aho-Corasick automaton:
 *   Phase 1 — Build trie from dictionary.
 *   Phase 2 — BFS to compute failure links and merged output sets.
 *   Phase 3 — Scan text via automaton (single pass, O(n + m)).
 *
 * Distinctive decompiler idioms:
 *   1. Trie insert: `ac_goto[cur][c] = ac_new_node(); cur = ...`
 *   2. BFS fail-link build: `fail[v] = ac_goto[fail[u]][c]`
 *   3. Output merge: `output[v] |= output[fail[v]]`
 *   4. Goto completion: `ac_goto[u][c] = ac_goto[fail[u]][c]` for missing
 *   5. Search: `cur = ac_goto[cur][c]` + popcount on output bitmask
 *
 * Dictionary: {"he"=bit0, "she"=bit1, "his"=bit2, "hers"=bit3}
 * Text: "ushers" (length 6)
 *
 * Matches:
 *   "she" at position 1 (she⊆ushers[1..3])
 *   "he"  at position 2 (he⊆ushers[2..3])
 *   "hers" at position 2 (hers⊆ushers[2..5])
 * Total match_count = 3
 *
 * n_patterns = 4
 * text_len   = 6
 * match_count= 3
 *
 * g_result = (n_patterns << 16) | (text_len << 8) | match_count = 0x00040603
 */
#include <stdint.h>

volatile uint32_t g_result;

#define AC_MAXNODES 20
#define AC_ALPHA    26

static int ac_goto[AC_MAXNODES][AC_ALPHA];
static int ac_fail[AC_MAXNODES];
static int ac_output[AC_MAXNODES];  /* bitmask: bit k set if pattern k ends here */
static int ac_size;
static int ac_queue[AC_MAXNODES];

/* ── Trie node allocator ──────────────────────────────────────────────────── */

static int ac_new_node(void)
{
    int id = ac_size++;
    for (int c = 0; c < AC_ALPHA; c++) ac_goto[id][c] = -1;
    ac_fail[id]   = 0;
    ac_output[id] = 0;
    return id;
}

/* ── Trie insertion ───────────────────────────────────────────────────────── */

static void ac_insert(const char *pat, int pat_id)
{
    int cur = 0;
    for (int i = 0; pat[i]; i++) {
        int c = pat[i] - 'a';
        if (ac_goto[cur][c] == -1)
            ac_goto[cur][c] = ac_new_node();
        cur = ac_goto[cur][c];
    }
    ac_output[cur] |= (1 << pat_id);
}

/* ── BFS: build failure links + complete goto function ───────────────────── */

static void ac_build(void)
{
    int head = 0, tail = 0;

    /* Initialise root: missing chars loop back to root */
    for (int c = 0; c < AC_ALPHA; c++) {
        if (ac_goto[0][c] == -1) {
            ac_goto[0][c] = 0;
        } else {
            ac_fail[ac_goto[0][c]] = 0;
            ac_queue[tail++] = ac_goto[0][c];
        }
    }

    while (head < tail) {
        int u = ac_queue[head++];
        for (int c = 0; c < AC_ALPHA; c++) {
            int v = ac_goto[u][c];
            if (v == -1) {
                /* Complete goto: redirect missing transition via fail */
                ac_goto[u][c] = ac_goto[ac_fail[u]][c];
            } else {
                ac_fail[v]   = ac_goto[ac_fail[u]][c];
                ac_output[v] |= ac_output[ac_fail[v]];
                ac_queue[tail++] = v;
            }
        }
    }
}

/* ── Text search ──────────────────────────────────────────────────────────── */

static int ac_search(const char *text)
{
    int count = 0, cur = 0;
    for (int i = 0; text[i]; i++) {
        cur = ac_goto[cur][text[i] - 'a'];
        int mask = ac_output[cur];
        while (mask) { count++; mask &= mask - 1; }  /* popcount of matches */
    }
    return count;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_aho_corasick(void)
{
    ac_size = 0;
    ac_new_node();  /* root = node 0 */

    /* Insert dictionary: he, she, his, hers */
    static const char pat0[] = "he";
    static const char pat1[] = "she";
    static const char pat2[] = "his";
    static const char pat3[] = "hers";
    ac_insert(pat0, 0);
    ac_insert(pat1, 1);
    ac_insert(pat2, 2);
    ac_insert(pat3, 3);

    ac_build();

    static const char text[] = "ushers";
    int matches = ac_search(text);   /* 3: "she", "he", "hers" */

    /* n_patterns=4, text_len=6, matches=3 */
    g_result = (4u << 16) | (6u << 8) | (uint32_t)matches;
}

__attribute__((noreturn)) void _start(void)
{
    test_aho_corasick();
    for (;;);
}
