/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Ukkonen's online suffix tree construction.
 *
 * Ukkonen's algorithm builds a suffix tree in O(n) by maintaining three
 * "active point" variables and applying three rules in each extension step.
 *
 * Distinctive decompiler idioms:
 *   1. active_node, active_edge, active_length — the active point triple
 *   2. remainder counter incremented before attempting extension
 *   3. suffix_link[v] set when a new internal node is created (rule 2)
 *   4. active_node = suffix_link[active_node] after following a suffix link
 *   5. need_suffix_link = -1 sentinel for pending suffix link
 *
 * Input: "abcabx"  (n=6)
 * Suffix tree has 6 leaf suffixes, 2 internal nodes (root + one split).
 * After construction: node_count = 2 internal + 1 root = 3
 *
 * We probe: does the tree contain "bca"? (yes) and "xyz"? (no).
 * g_result = (node_count << 16) | (contains_bca << 8) | contains_xyz
 *          = (3 << 16) | (1 << 8) | 0
 *          = 0x030100 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define UK_MAXN   8
#define UK_ALPHA  6    /* a=0 b=1 c=2 x=3 (compact alphabet) */
#define UK_INF    0x7FFFFFFF

typedef struct {
    int start, end;         /* edge label: s[start..end] */
    int link;               /* suffix link (-1 = none) */
    int next[UK_ALPHA];     /* children by first character */
} UKNode;

static UKNode uk_nodes[UK_MAXN * 4];
static int    uk_node_cnt;
static int    uk_text[UK_MAXN];
static int    uk_n;

static int uk_new_node(int start, int end) {
    int id = uk_node_cnt++;
    uk_nodes[id].start = start;
    uk_nodes[id].end   = end;
    uk_nodes[id].link  = 0;   /* 0 = root */
    for (int i = 0; i < UK_ALPHA; i++) uk_nodes[id].next[i] = -1;
    return id;
}

static int uk_edge_len(int v, int phase) {
    int e = uk_nodes[v].end;
    return (e == UK_INF ? phase + 1 : e) - uk_nodes[v].start;
}

static void uk_build(void) {
    /* root is node 0 */
    uk_node_cnt = 0;
    int root = uk_new_node(-1, -1);  /* root: start=-1, end=-1 (length 0) */
    (void)root;

    int active_node   = 0;
    int active_edge   = -1;
    int active_length = 0;
    int remainder     = 0;
    int need_link     = -1;

    for (int i = 0; i < uk_n; i++) {
        int c = uk_text[i];
        need_link = -1;
        remainder++;

        while (remainder > 0) {
            if (active_length == 0) active_edge = c;

            if (uk_nodes[active_node].next[active_edge] == -1) {
                /* Rule 2: no edge — create leaf */
                int leaf = uk_new_node(i, UK_INF);
                uk_nodes[active_node].next[active_edge] = leaf;
                if (need_link != -1) {
                    uk_nodes[need_link].link = active_node;
                    need_link = -1;
                }
            } else {
                int nxt = uk_nodes[active_node].next[active_edge];
                int el  = uk_edge_len(nxt, i);
                if (active_length >= el) {
                    /* Walk down */
                    active_edge    = uk_text[uk_nodes[nxt].start + active_length];
                    active_length -= el;
                    active_node    = nxt;
                    continue;
                }
                /* Check if current character matches */
                if (uk_text[uk_nodes[nxt].start + active_length] == c) {
                    active_length++;
                    if (need_link != -1) {
                        uk_nodes[need_link].link = active_node;
                    }
                    break; /* Rule 3: already in tree */
                }
                /* Rule 2: split */
                int split = uk_new_node(uk_nodes[nxt].start,
                                        uk_nodes[nxt].start + active_length);
                uk_nodes[active_node].next[active_edge] = split;
                int leaf2 = uk_new_node(i, UK_INF);
                uk_nodes[split].next[c] = leaf2;
                uk_nodes[nxt].start += active_length;
                uk_nodes[split].next[uk_text[uk_nodes[nxt].start]] = nxt;
                if (need_link != -1) uk_nodes[need_link].link = split;
                need_link = split;
            }
            remainder--;
            if (active_node == 0 && active_length > 0) {
                active_length--;
                active_edge = uk_text[i - remainder + 1];
            } else if (uk_nodes[active_node].link > 0) {
                active_node = uk_nodes[active_node].link;
            } else {
                active_node = 0;
            }
        }
    }
}

/* Search for pattern in the suffix tree */
static int uk_search(int *pat, int plen) {
    int v = 0, d = 0, pi = 0;
    while (pi < plen) {
        if (d == 0) {
            int c = pat[pi];
            int nxt = uk_nodes[v].next[c];
            if (nxt == -1) return 0;
            /* consume the first edge char (matched by selecting this edge) */
            v = nxt; d = 1; pi++;
        }
        int es = uk_nodes[v].start;
        int ee = uk_nodes[v].end == UK_INF ? uk_n : uk_nodes[v].end;
        /* compare remaining edge chars (es+1 .. ee-1) with pat[pi..] */
        while (d < (ee - es) && pi < plen) {
            if (uk_text[es + d] != pat[pi]) return 0;
            d++; pi++;
        }
        if (pi < plen && d == (ee - es)) {
            /* consumed entire edge — walk to child */
            int c2 = pat[pi];
            int nxt2 = uk_nodes[v].next[c2];
            if (nxt2 == -1) return 0;
            v = nxt2; d = 1; pi++;
        } else {
            break;
        }
    }
    return 1;
}

void test_ukkonen(void)
{
    /* "abcabx" mapped to compact alphabet: a=0,b=1,c=2,x=3 */
    uk_text[0] = 0; uk_text[1] = 1; uk_text[2] = 2;
    uk_text[3] = 0; uk_text[4] = 1; uk_text[5] = 3;
    uk_n = 6;

    uk_build();

    /* Count internal nodes (start != -1, end != INF and not leaf start<end) */
    int internal = 0;
    for (int i = 0; i < uk_node_cnt; i++) {
        int es = uk_nodes[i].start, ee = uk_nodes[i].end;
        /* internal node: has children AND not a leaf label stretching to INF */
        int has_child = 0;
        for (int j = 0; j < UK_ALPHA; j++)
            if (uk_nodes[i].next[j] != -1) { has_child = 1; break; }
        if (has_child && !(es == -1 && ee == -1)) internal++;
    }
    /* root is the extra internal node (es==-1, ee==-1) */
    internal++; /* count root */

    /* Search "bca" = {1,2,0} */
    int pat_bca[3] = {1, 2, 0};
    int found_bca = uk_search(pat_bca, 3);

    /* Search "xyz" = {3,??,?} — x=3 followed by chars not in text */
    int pat_xyz[3] = {3, 2, 1};
    int found_xyz = uk_search(pat_xyz, 3);

    g_result = ((uint32_t)internal << 16)
             | ((uint32_t)(found_bca & 1) << 8)
             | ((uint32_t)(found_xyz & 1));
}

__attribute__((noreturn)) void _start(void)
{
    test_ukkonen();
    for (;;);
}
