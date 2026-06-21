/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Palindrome Tree (Eertree) fixture.
 *
 * The Palindrome Tree (Eertree) is an implicit trie of all distinct palindromic
 * substrings of a string.  Two imaginary roots:
 *   node 0: length -1 (odd root), suffix link → itself
 *   node 1: length  0 (even root), suffix link → node 0
 *
 * For each new character we walk suffix links to find the longest palindromic
 * suffix that can be extended by the current character.
 *
 * Test string: "abaacabaac"  (length 10, palindromes to find: a, b, aba, aa, aabaa,
 *               baab, abaaba, c, ac... but exact distinct count is what we measure)
 *
 * Simpler test: "aabaa"  (length 5)
 *   Distinct palindromic substrings: "a", "aa", "b", "aba", "aabaa"  → 5 distinct
 *   Occurrences of "aa" (length 2) → 1
 *
 * Metrics:
 *   n_tests  = 5   (length of test string)
 *   metric_a = 5   (number of distinct palindromic substrings)
 *   metric_b = 3   (number of palindromic substrings of length > 1: aa, aba, aabaa)
 * g_result = (5<<16)|(5<<8)|3 = 0x050503
 */

#include <stdint.h>

volatile uint32_t g_result;

#define PT_ALPHA  26
#define PT_MAXN   32   /* at most 2+n distinct palindromes for string of length n */

typedef struct {
    int  len;              /* length of palindrome at this node */
    int  link;             /* longest proper palindromic suffix link */
    int  ch[PT_ALPHA];     /* children: extending character on both sides */
} PTNode;

static PTNode pt[PT_MAXN];
static int    pt_sz;       /* number of nodes */
static int    pt_last;     /* last node appended */

/* the string is stored so we can check palindrome extension */
static int    pt_str[64];
static int    pt_len;

static void pt_init(void) {
    pt_sz  = 0;
    pt_len = 0;

    /* node 0: odd root, length -1, suffix link → itself */
    pt[0].len  = -1;
    pt[0].link =  0;
    for (int i = 0; i < PT_ALPHA; i++) pt[0].ch[i] = -1;
    pt_sz++;

    /* node 1: even root, length 0, suffix link → 0 */
    pt[1].len  =  0;
    pt[1].link =  0;
    for (int i = 0; i < PT_ALPHA; i++) pt[1].ch[i] = -1;
    pt_sz++;

    pt_last = 1;
}

/* get_link(v, pos): find longest palindromic suffix of str[0..pos] that can be
   extended on both sides by str[pos] */
static int pt_get_link(int v, int pos) {
    while (1) {
        /* check if str[pos - len(v) - 1] == str[pos] */
        int left = pos - pt[v].len - 1;
        if (left >= 0 && pt_str[left] == pt_str[pos]) return v;
        v = pt[v].link;
    }
}

static void pt_add(int c) {
    pt_str[pt_len++] = c;
    int pos  = pt_len - 1;
    int cur  = pt_get_link(pt_last, pos);
    int cc   = pt_str[pos];

    if (pt[cur].ch[cc] == -1) {
        /* create new node */
        int nw = pt_sz++;
        pt[nw].len = pt[cur].len + 2;
        for (int i = 0; i < PT_ALPHA; i++) pt[nw].ch[i] = -1;

        /* set suffix link for new node */
        if (pt[nw].len == 1) {
            pt[nw].link = 1;   /* single char → even root */
        } else {
            int lnk = pt_get_link(pt[cur].link, pos);
            pt[nw].link = pt[lnk].ch[cc];
        }
        pt[cur].ch[cc] = nw;
    }
    pt_last = pt[cur].ch[cc];
}

void _start(void) {
    pt_init();

    const char s[] = "aabaa";
    int slen = 5;
    for (int i = 0; i < slen; i++) pt_add(s[i] - 'a');

    /* distinct palindromic substrings = pt_sz - 2 (exclude two imaginary roots) */
    int distinct = pt_sz - 2;  /* expect 5: a, aa, b, aba, aabaa */

    /* count nodes with length > 1 */
    int longer = 0;
    for (int i = 2; i < pt_sz; i++) {
        if (pt[i].len > 1) longer++;
    }
    /* aa(2), aba(3), aabaa(5) → 3 */

    uint32_t n_tests  = (uint32_t)slen;          /* 5 */
    uint32_t metric_a = (uint32_t)(distinct & 0xFF); /* 5 */
    uint32_t metric_b = (uint32_t)(longer   & 0xFF); /* 3 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    /* expected: 0x050503 */
    while (1) {}
}
