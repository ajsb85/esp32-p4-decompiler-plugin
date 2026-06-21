/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Aho-Corasick DP fixture.
 *
 * Aho-Corasick automaton combined with dynamic programming counts strings
 * of length N over alphabet {a,b} that do NOT contain any forbidden pattern.
 *
 * Algorithm:
 *   1. Build Aho-Corasick trie from forbidden patterns with failure links
 *   2. DP: dp[len][state] = # strings of length `len` ending in AC state
 *   3. For each length step, follow goto/failure transitions for each char
 *   4. Sum over all non-accepting states gives count of valid strings
 *
 * Distinctive decompiler idioms:
 *   1. Failure link BFS: `fail[child] = goto[fail[parent]][c]`
 *   2. State acceptance propagation: `accept[s] |= accept[fail[s]]`
 *   3. DP transition: `ndp[nxt] += dp[s]` accumulated via goto links
 *   4. Output function: skip states where `accept[s]` is set
 *
 * Test: forbidden patterns = {"aa", "bb"}, string length = 4, alphabet = {a=0, b=1}
 *   Valid strings of length 4 that contain neither "aa" nor "bb":
 *   Only alternating strings are valid: abab, abba (invalid-has bb), baba, baab (invalid)
 *   Valid: abab, baba, abba? No: "abba" contains "bb".
 *   Systematically: "abab" ok, "baba" ok, "abab" already listed.
 *   Let me enumerate: must alternate. Length 4: "abab" and "baba" = 2 strings.
 *
 * Result encoding:
 *   count = 2 (valid strings) — fits in byte
 *   n_patterns = 2 (forbidden patterns)
 *   checksum = (2 + 2) & 0xFF = 4 = 0x04
 *   g_result = (2<<16)|(2<<8)|4 = 0x020204
 *
 * But (2<<16)|(2<<8)|4: byte2=2, byte1=2 => not distinct!
 * Use string length=6: abab patterns over {a,b} avoiding "aa","bb"
 *   Only valid: alternating sequences starting with a or b = 2 strings still.
 *   Use length=5: ababa, babab = 2 strings.
 * Use length=8: still 2 (only abababab, babababa).
 *
 * Change encoding: count=2, strlen=4, checksum=(2+4)=6
 *   g_result = (2<<16)|(4<<8)|6 = 0x020406
 *   bytes: 2,4,6 — non-zero, distinct. Good.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define AC_ALPHA  2u   /* alphabet size: {a=0, b=1} */
#define AC_NODES  8u   /* max trie nodes */
#define AC_SLEN   4u   /* string length for DP */

static uint32_t ac_goto[AC_NODES][AC_ALPHA];
static uint32_t ac_fail[AC_NODES];
static uint32_t ac_accept[AC_NODES];
static uint32_t ac_size;

/* BFS queue */
static uint32_t ac_queue[AC_NODES];

static void ac_init(void)
{
    for (uint32_t i = 0u; i < AC_NODES; i++) {
        for (uint32_t c = 0u; c < AC_ALPHA; c++) {
            ac_goto[i][c] = 0u;
        }
        ac_fail[i]   = 0u;
        ac_accept[i] = 0u;
    }
    ac_size = 1u; /* root = 0 */
}

static void ac_insert(const uint32_t *pat, uint32_t plen)
{
    uint32_t cur = 0u;
    for (uint32_t i = 0u; i < plen; i++) {
        uint32_t c = pat[i];
        if (ac_goto[cur][c] == 0u) {
            ac_goto[cur][c] = ac_size++;
        }
        cur = ac_goto[cur][c];
    }
    ac_accept[cur] = 1u;
}

static void ac_build(void)
{
    /* BFS to set failure links */
    uint32_t qhead = 0u, qtail = 0u;
    for (uint32_t c = 0u; c < AC_ALPHA; c++) {
        uint32_t s = ac_goto[0][c];
        if (s != 0u) {
            ac_fail[s] = 0u;
            ac_queue[qtail++] = s;
        }
    }
    while (qhead < qtail) {
        uint32_t u = ac_queue[qhead++];
        /* Propagate accept via failure links */
        if (ac_accept[ac_fail[u]]) ac_accept[u] = 1u;
        for (uint32_t c = 0u; c < AC_ALPHA; c++) {
            uint32_t v = ac_goto[u][c];
            if (v != 0u) {
                ac_fail[v] = ac_goto[ac_fail[u]][c];
                ac_queue[qtail++] = v;
            } else {
                /* Complete automaton: missing transitions -> failure state */
                ac_goto[u][c] = ac_goto[ac_fail[u]][c];
            }
        }
    }
}

void test_aho_corasick_dp(void)
{
    ac_init();

    /* Forbidden patterns: "aa" = {0,0}, "bb" = {1,1} */
    uint32_t pat_aa[2] = {0u, 0u};
    uint32_t pat_bb[2] = {1u, 1u};
    ac_insert(pat_aa, 2u);
    ac_insert(pat_bb, 2u);
    ac_build();

    /* DP: dp[s] = number of strings of current length ending in state s */
    uint32_t dp[AC_NODES];
    uint32_t ndp[AC_NODES];
    for (uint32_t i = 0u; i < AC_NODES; i++) dp[i] = 0u;
    dp[0] = 1u; /* empty string starts at root */

    for (uint32_t step = 0u; step < AC_SLEN; step++) {
        for (uint32_t i = 0u; i < AC_NODES; i++) ndp[i] = 0u;
        for (uint32_t s = 0u; s < ac_size; s++) {
            if (dp[s] == 0u || ac_accept[s]) continue; /* skip forbidden states */
            for (uint32_t c = 0u; c < AC_ALPHA; c++) {
                uint32_t nxt = ac_goto[s][c];
                if (!ac_accept[nxt]) {
                    ndp[nxt] += dp[s];
                }
            }
        }
        for (uint32_t i = 0u; i < AC_NODES; i++) dp[i] = ndp[i];
    }

    /* Sum over all non-accepting states */
    uint32_t count = 0u;
    for (uint32_t s = 0u; s < ac_size; s++) {
        if (!ac_accept[s]) count += dp[s];
    }
    /* count=2 (abab, baba), strlen=AC_SLEN=4 */
    uint32_t strlen_u  = AC_SLEN & 0xFFu;
    uint32_t checksum  = (count + strlen_u) & 0xFFu;
    g_result = (count << 16) | (strlen_u << 8) | checksum;
}

__attribute__((noreturn)) void _start(void)
{
    test_aho_corasick_dp();
    for (;;);
}
