/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Prefix-trie round-trip fixture.
 *
 * Exercises a classic lowercase-alphabet trie with a static node pool and
 * 26-element children arrays (indexed by `ch - 'a'`).  The children-array
 * access and is_end flag are highly recognizable idioms in decompiled output:
 *   node.children[c] = alloc();   ← insert
 *   if (node.children[c] < 0) return 0;  ← search miss
 *
 * Words inserted (6):  "cat", "car", "card", "care", "dog", "door"
 * XOR of word lengths:  3^3^4^4^3^4 = 7
 * Sum of word lengths:  3+3+4+4+3+4 = 21 (not used in g_result — recorded below)
 *
 * Search queries (8):
 *   "cat"  → 1  (is_end)
 *   "ca"   → 0  (exists as prefix; not a word)
 *   "care" → 1
 *   "card" → 1
 *   "do"   → 0
 *   "dog"  → 1
 *   "door" → 1
 *   "bat"  → 0  (not present)
 *   found_count = 5
 *
 * g_result = (word_count << 16) | (found_count << 8) | xor_len
 *           = (6 << 16) | (5 << 8) | 7
 *           = 0x00060507
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Static trie pool ────────────────────────────────────────────────────── */

#define TRIE_MAX  64
#define ALPHA     26

typedef struct {
    int children[ALPHA];
    int is_end;
} TNode;

static TNode tpool[TRIE_MAX];
static int   tpool_n;

/* ── Node allocator ──────────────────────────────────────────────────────── */

static int trie_alloc(void)
{
    int i = tpool_n++;
    for (int c = 0; c < ALPHA; c++)
        tpool[i].children[c] = -1;
    tpool[i].is_end = 0;
    return i;
}

/* ── Insert ──────────────────────────────────────────────────────────────── */

static void trie_insert(const char *word)
{
    int cur = 0; /* root is node 0 */
    for (int i = 0; word[i] != '\0'; i++) {
        int c = word[i] - 'a';
        if (tpool[cur].children[c] < 0)
            tpool[cur].children[c] = trie_alloc();
        cur = tpool[cur].children[c];
    }
    tpool[cur].is_end = 1;
}

/* ── Search ──────────────────────────────────────────────────────────────── */

static int trie_search(const char *word)
{
    int cur = 0;
    for (int i = 0; word[i] != '\0'; i++) {
        int c = word[i] - 'a';
        if (tpool[cur].children[c] < 0)
            return 0;
        cur = tpool[cur].children[c];
    }
    return tpool[cur].is_end;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_trie(void)
{
    static const char * const words[6] = {
        "cat", "car", "card", "care", "dog", "door"
    };
    static const char * const queries[8] = {
        "cat", "ca", "care", "card", "do", "dog", "door", "bat"
    };

    /* Reset pool; root = first allocated node */
    tpool_n = 0;
    trie_alloc(); /* node 0 = root */

    uint32_t xor_len = 0;
    for (int i = 0; i < 6; i++) {
        trie_insert(words[i]);
        uint32_t len = 0;
        for (const char *p = words[i]; *p; p++) len++;
        xor_len ^= len;
    }

    uint32_t found = 0;
    for (int i = 0; i < 8; i++)
        found += (uint32_t)trie_search(queries[i]);

    g_result = (6u << 16) | (found << 8) | (xor_len & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_trie();
    for (;;);
}
