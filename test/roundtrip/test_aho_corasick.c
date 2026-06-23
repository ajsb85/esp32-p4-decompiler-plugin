/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Aho-Corasick multi-pattern string matching.
 *
 * Aho-Corasick builds a finite automaton from a set of patterns, then
 * scans a text in O(n + m + z) where z is the number of matches.
 *
 * Distinctive decompiler idioms:
 *   1. BFS queue during failure link construction (not DFS)
 *   2. fail[child] = goto[fail[parent]][c] — failure link propagation
 *   3. output[v] |= output[fail[v]] — output link chaining
 *   4. state = goto_fn[state][c] during text scan
 *   5. popcount(output[state]) per char — count patterns per state via bitmask
 *
 * Patterns: {"he","she","his","hers"}  Text: "ushers"
 * Trie states: 10 (root + 9 trie nodes for 4 patterns)
 * Matches:  "she"@2 + "he"@2 (via fail[she]=he) + "hers"@5 = 3 total
 *
 * g_result = (n_states << 16) | (matches << 8) | 0
 *          = (10 << 16) | (3 << 8) | 0
 *          = 0x0A0300 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define AC_ALPHA  26
#define AC_MAXS   16

static int  ac_goto[AC_MAXS][AC_ALPHA];
static int  ac_fail[AC_MAXS];
static int  ac_out[AC_MAXS];   /* bitmask: bit k set if pattern k ends here */
static int  ac_sz;

/* Tiny BFS queue */
static int  ac_q[AC_MAXS];

static int ac_new(void) {
    int id = ac_sz++;
    ac_fail[id] = 0;
    ac_out[id]  = 0;
    for (int i = 0; i < AC_ALPHA; i++) ac_goto[id][i] = -1;
    return id;
}

static void ac_insert(const char *pat, int mask) {
    int cur = 0;
    for (int i = 0; pat[i]; i++) {
        int c = pat[i] - 'a';
        if (ac_goto[cur][c] == -1)
            ac_goto[cur][c] = ac_new();
        cur = ac_goto[cur][c];
    }
    ac_out[cur] |= mask;
}

static void ac_build(void) {
    /* Fill missing root transitions with 0 (root loops) */
    int head = 0, tail = 0;
    for (int c = 0; c < AC_ALPHA; c++) {
        if (ac_goto[0][c] == -1) {
            ac_goto[0][c] = 0;
        } else {
            ac_fail[ac_goto[0][c]] = 0;
            ac_q[tail++] = ac_goto[0][c];
        }
    }
    while (head < tail) {
        int u = ac_q[head++];
        for (int c = 0; c < AC_ALPHA; c++) {
            int v = ac_goto[u][c];
            if (v == -1) {
                ac_goto[u][c] = ac_goto[ac_fail[u]][c];
            } else {
                ac_fail[v] = ac_goto[ac_fail[u]][c];
                ac_out[v] |= ac_out[ac_fail[v]];
                ac_q[tail++] = v;
            }
        }
    }
}

static int ac_search(const char *text) {
    int state = 0, matches = 0;
    for (int i = 0; text[i]; i++) {
        state = ac_goto[state][text[i] - 'a'];
        /* popcount: count individual pattern matches via output bitmask */
        int out = ac_out[state];
        while (out) { matches += out & 1; out >>= 1; }
    }
    return matches;
}

void test_aho_corasick(void)
{
    ac_sz = 0;
    ac_new();  /* state 0 = root */

    /* patterns: "he"=1, "she"=2, "his"=4, "hers"=8 */
    ac_insert("he",   1);
    ac_insert("she",  2);
    ac_insert("his",  4);
    ac_insert("hers", 8);

    ac_build();

    int n_states = ac_sz;          /* 10 */
    int matches  = ac_search("ushers");  /* 3: she@2, he@2 (via fail link), hers@5 */

    g_result = ((uint32_t)n_states << 16)
             | ((uint32_t)matches  <<  8);
}

__attribute__((noreturn)) void _start(void)
{
    test_aho_corasick();
    for (;;);
}
