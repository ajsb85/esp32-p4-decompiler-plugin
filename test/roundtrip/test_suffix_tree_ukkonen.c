/* test_suffix_tree_ukkonen.c
 * Purpose   : Validate Ukkonen's online suffix tree construction
 * Algorithm : Ukkonen builds an implicit suffix tree in O(n) time using
 *             active point (node, edge, length), remaining count, and suffix links.
 *             A sentinel character '$' makes all suffixes explicit leaves.
 *             Key idioms: active point walk-down, split internal node creation,
 *             suffix link chaining (last_new->link = new_internal).
 * Input     : "abcabc$" (original "abcabc", n=6, with sentinel)
 * Expected  : distinct substrings of "abcabc" = 15
 *             leaves in suffix tree = 7 (one per suffix incl. empty after $)
 *             n_orig = 6
 * g_result  = (n_orig << 16) | (distinct << 8) | n_leaves
 *           = (6 << 16) | (15 << 8) | 7 = 0x060F07
 */

#include <stdint.h>

volatile uint32_t g_result;

#define UKON_ALPHA  27   /* 'a'-'z' (0-25) plus '$' (26) */
#define UKON_MAXN   16   /* enough nodes for "abcabc$" (n=7) */
#define UKON_INF    9999

typedef struct {
    int ch[UKON_ALPHA];
    int link;   /* suffix link; 0 = root */
    int start;
    int end;    /* UKON_INF = open leaf (grows with g_end) */
} UNode;

static UNode ukon_nd[UKON_MAXN];
static int   ukon_cnt;
static int   ukon_g_end;    /* current rightmost position (exclusive) */
static int   ukon_last_new; /* last unresolved internal node */

static const char ukon_raw[] = "abcabc";
static char  ukon_s[10];    /* "abcabc$\0" */
static int   ukon_n;        /* length including '$' */

static int ukon_char_idx(char c) {
    return (c == '$') ? 26 : (c - 'a');
}

static int ukon_new_node(int start, int end) {
    int id = ukon_cnt++;
    for (int i = 0; i < UKON_ALPHA; i++) ukon_nd[id].ch[i] = -1;
    ukon_nd[id].link  = 0;
    ukon_nd[id].start = start;
    ukon_nd[id].end   = end;
    return id;
}

static int ukon_edge_len(int id) {
    int e = (ukon_nd[id].end == UKON_INF) ? ukon_g_end : ukon_nd[id].end;
    if (ukon_nd[id].start < 0) return 0; /* root */
    return e - ukon_nd[id].start;
}

static void ukon_build(void) {
    /* Append sentinel */
    int raw_n = 0;
    while (ukon_raw[raw_n]) { ukon_s[raw_n] = ukon_raw[raw_n]; raw_n++; }
    ukon_s[raw_n] = '$';
    ukon_n = raw_n + 1;
    ukon_s[ukon_n] = '\0';

    ukon_cnt = 0;
    ukon_new_node(-1, -1); /* root = node 0 */

    int an  = 0;  /* active node */
    int ae  = -1; /* active edge (char index) */
    int al  = 0;  /* active length */
    int rem = 0;  /* remaining suffixes to insert */
    ukon_last_new = -1;

    for (int i = 0; i < ukon_n; i++) {
        ukon_g_end = i + 1;
        rem++;
        ukon_last_new = -1;

        while (rem > 0) {
            if (al == 0) ae = ukon_char_idx(ukon_s[i]);

            if (ukon_nd[an].ch[ae] == -1) {
                /* Rule 2: no edge — create leaf */
                ukon_nd[an].ch[ae] = ukon_new_node(i, UKON_INF);
                if (ukon_last_new != -1) {
                    ukon_nd[ukon_last_new].link = an;
                    ukon_last_new = -1;
                }
            } else {
                int nxt = ukon_nd[an].ch[ae];
                int el  = ukon_edge_len(nxt);
                if (al >= el) {
                    /* Walk down the tree */
                    ae = ukon_char_idx(ukon_s[i - al + el]);
                    al -= el;
                    an  = nxt;
                    continue;
                }
                /* Rule 3: char already on edge — extend implicitly */
                if (ukon_s[ukon_nd[nxt].start + al] == ukon_s[i]) {
                    al++;
                    if (ukon_last_new != -1)
                        ukon_nd[ukon_last_new].link = an;
                    break;
                }
                /* Rule 2: split edge — create internal node */
                int spl = ukon_new_node(ukon_nd[nxt].start,
                                        ukon_nd[nxt].start + al);
                ukon_nd[an].ch[ae] = spl;
                /* New leaf for current char */
                ukon_nd[spl].ch[ukon_char_idx(ukon_s[i])] = ukon_new_node(i, UKON_INF);
                /* Old child edge starts after the split point */
                ukon_nd[nxt].start += al;
                ukon_nd[spl].ch[ukon_char_idx(ukon_s[ukon_nd[nxt].start])] = nxt;
                /* Chain suffix link */
                if (ukon_last_new != -1) ukon_nd[ukon_last_new].link = spl;
                ukon_last_new = spl;
            }
            rem--;
            if (an == 0 && al > 0) {
                al--;
                ae = ukon_char_idx(ukon_s[i - rem + 1]);
            } else if (ukon_nd[an].link != 0) {
                an = ukon_nd[an].link;
            } else {
                an = 0;
            }
        }
    }
}

/* Sum edge lengths, excluding edges that contain '$' (to count original substrings) */
static int ukon_count_distinct(int id) {
    int tot = 0;
    for (int c = 0; c < 26; c++) { /* only 'a'-'z', skip '$' */
        int ch = ukon_nd[id].ch[c];
        if (ch == -1) continue;
        int start = ukon_nd[ch].start;
        int end   = (ukon_nd[ch].end == UKON_INF) ? ukon_g_end : ukon_nd[ch].end;
        int el    = end - start;
        /* Trim at '$' if present in this edge */
        for (int k = start; k < end; k++) {
            if (ukon_s[k] == '$') { el = k - start; break; }
        }
        tot += el;
        tot += ukon_count_distinct(ch);
    }
    return tot;
}

/* Count leaf nodes (all children == -1) */
static int ukon_count_leaves(int id) {
    int is_leaf = 1, cnt = 0;
    for (int c = 0; c < UKON_ALPHA; c++) {
        if (ukon_nd[id].ch[c] != -1) {
            is_leaf = 0;
            cnt += ukon_count_leaves(ukon_nd[id].ch[c]);
        }
    }
    return is_leaf ? 1 : cnt;
}

void _start(void) {
    ukon_build();

    int distinct = ukon_count_distinct(0);   /* 15 */
    int n_leaves = ukon_count_leaves(0);     /* 7  */
    int n_orig   = ukon_n - 1;              /* 6  */

    /* (6 << 16) | (15 << 8) | 7 = 0x060F07 */
    g_result = ((uint32_t)n_orig   << 16)
             | ((uint32_t)distinct <<  8)
             | ((uint32_t)n_leaves);
    while (1) {}
}
