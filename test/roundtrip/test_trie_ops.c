/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Trie Insert/Search Operations fixture.
 *
 * Implements a trie using flat arrays (no dynamic allocation).
 * Insert: {"apple","app","application","apt"}
 * Search: tests both exact matches and prefix-only non-matches.
 *
 * Distinctive decompiler idioms:
 *   1. `tr_ch[cur][c]` — child pointer lookup by character index
 *   2. `if(!tr_ch[cur][c]){ n=tr_sz++; ... } cur=tr_ch[cur][c]` — insert walk
 *   3. `tr_end[cur]=1` — mark end of word on insert
 *   4. `return tr_end[cur]` — search: exact match requires is_end flag
 *
 * Queries: "app"→1,"apple"→1,"ap"→0,"application"→1,"xyz"→0,"apt"→1
 * n_queries=6, found=4, miss=2
 *
 * g_result = (6<<16)|(found<<8)|miss = 0x00060402
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Node 0 is the root; all arrays BSS-zero-initialized */
#define TR_MAX_NODES 60

static int tr_ch[TR_MAX_NODES][26];
static int tr_end[TR_MAX_NODES];
static int tr_sz;

/* tr_init: set root (node 0 already BSS-zero); tr_sz=1 means root exists */
static void tr_init(void)
{
    tr_sz = 1;
    /* BSS guarantees tr_ch[0] and tr_end[0] are zero — no explicit clear */
}

static void tr_insert(const char *s)
{
    int cur = 0;
    for (; *s; s++) {
        int c = *s - 'a';
        if (!tr_ch[cur][c]) {
            /* BSS guarantees new node slots start zero; no explicit clear needed */
            int nn = tr_sz++;
            tr_ch[cur][c] = nn;
        }
        cur = tr_ch[cur][c];
    }
    tr_end[cur] = 1;
}

static int tr_search(const char *s)
{
    int cur = 0;
    for (; *s; s++) {
        int c = *s - 'a';
        if (!tr_ch[cur][c]) return 0;
        cur = tr_ch[cur][c];
    }
    return tr_end[cur];
}

void test_trie_ops(void)
{
    static const char *words[4]   = {"apple", "app", "application", "apt"};
    static const char *queries[6] = {"app", "apple", "ap", "application", "xyz", "apt"};
    int i, found = 0, miss = 0;

    tr_init();
    for (i = 0; i < 4; i++) tr_insert(words[i]);

    for (i = 0; i < 6; i++) {
        if (tr_search(queries[i])) found++;
        else miss++;
    }
    /* found=4, miss=2 */
    g_result = (6u << 16) | ((uint32_t)found << 8) | (uint32_t)miss;
}

__attribute__((noreturn)) void _start(void)
{
    test_trie_ops();
    for (;;);
}
