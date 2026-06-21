/* test_suffix_automaton.c
 * Purpose   : Validate a Suffix Automaton (SAM) for substring queries.
 * Algorithm : Each sa_extend() call adds a character, doubling states
 *             with clone when the longest-path suffix link must split.
 *             The automaton recognises all substrings of the input string.
 * Input     : "abcbc"  (n=5)
 * Metrics   :
 *   n_tests  = 5   (characters fed to SAM)
 *   metric_a = number of states created  (expect 8 for "abcbc")
 *   metric_b = number of successful substring queries out of 5 asked
 *              queries: "a"(yes), "bc"(yes), "abc"(yes), "cb"(yes), "ac"(no)
 *              => 4 successes
 * g_result  = (5<<16)|(8<<8)|4 = 0x050804
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define SAM_ALPHA 26
#define SAM_MAXST 32   /* 2*n states suffice for string of length n=5 */

typedef struct {
    int len;            /* length of longest string in this state's class */
    int link;           /* suffix link */
    int next[SAM_ALPHA];/* transitions */
} SAMState;

static SAMState sam_st[SAM_MAXST];
static int      sam_sz;    /* number of states */
static int      sam_last;  /* last state after most recent extend */

static void sam_init(void) {
    sam_sz   = 0;
    /* state 0 = initial */
    sam_st[0].len  = 0;
    sam_st[0].link = -1;
    for (int c = 0; c < SAM_ALPHA; c++) sam_st[0].next[c] = -1;
    sam_sz   = 1;
    sam_last = 0;
}

static void sam_extend(int c) {
    /* Create new state */
    int cur = sam_sz++;
    sam_st[cur].len  = sam_st[sam_last].len + 1;
    sam_st[cur].link = -1;
    for (int i = 0; i < SAM_ALPHA; i++) sam_st[cur].next[i] = -1;

    int p = sam_last;
    /* Walk suffix links until we find a state with transition c */
    while (p != -1 && sam_st[p].next[c] == -1) {
        sam_st[p].next[c] = cur;
        p = sam_st[p].link;
    }
    if (p == -1) {
        sam_st[cur].link = 0;
    } else {
        int q = sam_st[p].next[c];
        if (sam_st[p].len + 1 == sam_st[q].len) {
            /* no clone needed */
            sam_st[cur].link = q;
        } else {
            /* clone q into clone */
            int clone = sam_sz++;
            sam_st[clone].len  = sam_st[p].len + 1;
            sam_st[clone].link = sam_st[q].link;
            for (int i = 0; i < SAM_ALPHA; i++)
                sam_st[clone].next[i] = sam_st[q].next[i];
            while (p != -1 && sam_st[p].next[c] == q) {
                sam_st[p].next[c] = clone;
                p = sam_st[p].link;
            }
            sam_st[q].link   = clone;
            sam_st[cur].link = clone;
        }
    }
    sam_last = cur;
}

/* Returns 1 if pattern (length plen) is a substring of the indexed string */
static int sam_contains(const char *pat, int plen) {
    int cur = 0;
    for (int i = 0; i < plen; i++) {
        int c = pat[i] - 'a';
        if (c < 0 || c >= SAM_ALPHA) return 0;
        if (sam_st[cur].next[c] == -1) return 0;
        cur = sam_st[cur].next[c];
    }
    return 1;
}

void _start(void) {
    sam_init();

    const char text[] = "abcbc";
    for (int i = 0; text[i]; i++) sam_extend(text[i] - 'a');

    int states = sam_sz;  /* expect 8 */

    int found = 0;
    found += sam_contains("a",   1);  /* yes */
    found += sam_contains("bc",  2);  /* yes */
    found += sam_contains("abc", 3);  /* yes */
    found += sam_contains("cb",  2);  /* yes */
    found += sam_contains("ac",  2);  /* no  */
    /* found = 4 */

    uint32_t n_tests  = 5;
    uint32_t metric_a = (uint32_t)(states & 0xFF);  /* 8 */
    uint32_t metric_b = (uint32_t)(found  & 0xFF);  /* 4 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    /* expected: 0x050804 */
    while (1) {}
}
