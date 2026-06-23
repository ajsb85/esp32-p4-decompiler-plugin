/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Suffix Automaton (SAM) / CDAWG construction.
 *
 * A Suffix Automaton (SAM) is the minimal DAWG that accepts all suffixes of a
 * string.  The online construction runs in O(n) time and O(n) space.
 *
 * Distinctive decompiler idioms:
 *   1. clone node when last->link->len + 1 < last->len (cloning step)
 *   2. link = sam_extend(); — last updated each iteration
 *   3. for (p = last; p != -1 && !next[p][c]; p = link[p]) — suffix chain walk
 *   4. if (len[q] == len[p]+1) — no clone needed shortcut
 *   5. transitions of clone copied from q, link of q reassigned to clone
 *
 * Input: "abcbc"  (n=5)
 * SAM for "abcbc": states=8, transitions=9 (compact alphabet a=0,b=1,c=2).
 * "bc" appears at positions 1 and 3 → 2 occurrences.
 *
 * g_result = (states << 16) | (transitions << 8) | occurrences_bc
 *          = (8 << 16) | (9 << 8) | 2
 *          = 0x080902 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SAM_MAXN  16
#define SAM_ALPHA  3   /* a=0, b=1, c=2 */

typedef struct {
    int len, link;
    int next[SAM_ALPHA];
    int cnt;          /* occurrence count (for substring counting) */
} SAMState;

static SAMState sam[SAM_MAXN * 2];
static int sam_sz, sam_last;

static int sam_new(int len) {
    int id = sam_sz++;
    sam[id].len  = len;
    sam[id].link = -1;
    sam[id].cnt  = 0;
    for (int i = 0; i < SAM_ALPHA; i++) sam[id].next[i] = -1;
    return id;
}

static void sam_init(void) {
    sam_sz = 0;
    sam_last = sam_new(0);   /* initial state */
}

static void sam_extend(int c) {
    /* Check if transition already exists (avoid duplicates) */
    if (sam[sam_last].next[c] != -1) {
        int q = sam[sam_last].next[c];
        if (sam[q].len == sam[sam_last].len + 1) {
            sam_last = q;
            return;
        }
        int clone = sam_new(sam[sam_last].len + 1);
        sam[clone].link = sam[q].link;
        for (int i = 0; i < SAM_ALPHA; i++) sam[clone].next[i] = sam[q].next[i];
        sam[clone].cnt = 0;
        sam[q].link = clone;
        int p = sam_last;
        while (p != -1 && sam[p].next[c] == q) {
            sam[p].next[c] = clone;
            p = sam[p].link;
        }
        sam_last = clone;
        return;
    }
    int cur = sam_new(sam[sam_last].len + 1);
    sam[cur].cnt = 1;
    int p = sam_last;
    while (p != -1 && sam[p].next[c] == -1) {
        sam[p].next[c] = cur;
        p = sam[p].link;
    }
    if (p == -1) {
        sam[cur].link = 0;
    } else {
        int q = sam[p].next[c];
        if (sam[q].len == sam[p].len + 1) {
            sam[cur].link = q;
        } else {
            int clone = sam_new(sam[p].len + 1);
            sam[clone].link = sam[q].link;
            for (int i = 0; i < SAM_ALPHA; i++) sam[clone].next[i] = sam[q].next[i];
            sam[clone].cnt = 0;
            sam[q].link = clone;
            sam[cur].link = clone;
            while (p != -1 && sam[p].next[c] == q) {
                sam[p].next[c] = clone;
                p = sam[p].link;
            }
        }
    }
    sam_last = cur;
}

/* Count occurrences of pattern in SAM by following transitions */
static int sam_count_occurrences(int *pat, int plen) {
    int cur = 0;
    for (int i = 0; i < plen; i++) {
        int c = pat[i];
        if (sam[cur].next[c] == -1) return 0;
        cur = sam[cur].next[c];
    }
    /* Count occurrences = sum of cnt for all states in the subtree of cur.
     * For a simple approach: topological order propagation was done at build.
     * Here we return cnt directly (set to 1 for each new suffix end state). */
    /* Simple topo propagation (insertion-order is reverse topo) */
    int occ[SAM_MAXN * 2];
    for (int i = 0; i < sam_sz; i++) occ[i] = sam[i].cnt;
    for (int i = sam_sz - 1; i >= 1; i--) {
        if (sam[i].link >= 0) occ[sam[i].link] += occ[i];
    }
    return occ[cur];
}

/* Count transitions in SAM */
static int sam_transition_count(void) {
    int t = 0;
    for (int i = 0; i < sam_sz; i++)
        for (int c = 0; c < SAM_ALPHA; c++)
            if (sam[i].next[c] != -1) t++;
    return t;
}

void test_suffix_automaton(void)
{
    /* "abcbc" → a=0, b=1, c=2 */
    int text[] = {0, 1, 2, 1, 2};
    int n = 5;

    sam_init();
    for (int i = 0; i < n; i++) sam_extend(text[i]);

    int states      = sam_sz;             /* 9 */
    int transitions = sam_transition_count(); /* 12 */

    int pat_bc[] = {1, 2};
    int occ_bc   = sam_count_occurrences(pat_bc, 2);  /* 2 */

    g_result = ((uint32_t)states      << 16)
             | ((uint32_t)transitions <<  8)
             | ((uint32_t)occ_bc);
}

__attribute__((noreturn)) void _start(void)
{
    test_suffix_automaton();
    for (;;);
}
