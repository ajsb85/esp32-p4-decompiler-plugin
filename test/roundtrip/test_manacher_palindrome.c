/* test_manacher_palindrome.c
 * Purpose   : Validate Manacher's O(n) algorithm for all palindromic substrings
 * Algorithm : Manacher's algorithm computes p[i] = radius of longest palindrome
 *             centred at i in O(n) time using a "mirror" trick: if i falls
 *             within the current rightmost palindrome [l,r], p[i] >= p[mirror]
 *             where mirror = 2*c - i (c = centre of [l,r]).  The algorithm
 *             only ever advances r, guaranteeing linear time.  Transforms
 *             string s into s' = "#a#b#..." to handle even-length palindromes
 *             uniformly.
 * Input     : "abaaba"  (n=6)
 * Expected  : Transformed: "#a#b#a#a#b#a#" (len=13)
 *             p[] = {0,1,0,3,0,1,6,1,0,3,0,1,0}
 *             max_radius=6 at centre 6 → palindrome "abaaba" (full string)
 *             count_ge1 = 7 (positions where p[i] >= 1)
 *             count_ge2 = 3 (positions where p[i] >= 2)
 * g_result  = (n << 16) | (count_ge1 << 8) | count_ge2
 *           = (6 << 16) | (7 << 8) | 3 = 0x060703
 */

#include <stdint.h>

volatile uint32_t g_result;

#define MAN_MAXN  64

static const char man_s[7] = "abaaba";
static char       man_t[MAN_MAXN];  /* transformed string */
static int        man_p[MAN_MAXN];
static int        man_tlen;

static void manacher(void) {
    /* Build transformed string: #a#b#a#... */
    int n = 6;
    man_tlen = 0;
    man_t[man_tlen++] = '#';
    for (int i = 0; i < n; i++) {
        man_t[man_tlen++] = man_s[i];
        man_t[man_tlen++] = '#';
    }

    int c = 0, r = 0;
    for (int i = 0; i < man_tlen; i++) {
        int mirror = 2 * c - i;
        if (i < r) {
            man_p[i] = (man_p[mirror] < r - i) ? man_p[mirror] : (r - i);
        } else {
            man_p[i] = 0;
        }
        /* Attempt to expand palindrome centred at i */
        while (i - man_p[i] - 1 >= 0 &&
               i + man_p[i] + 1 < man_tlen &&
               man_t[i - man_p[i] - 1] == man_t[i + man_p[i] + 1]) {
            man_p[i]++;
        }
        /* Update centre and right boundary */
        if (i + man_p[i] > r) {
            c = i;
            r = i + man_p[i];
        }
    }
}

void _start(void) {
    manacher();

    int count_ge1 = 0;  /* positions in t[] with p[i] >= 1 */
    int count_ge2 = 0;  /* positions in t[] with p[i] >= 2 */

    for (int i = 0; i < man_tlen; i++) {
        if (man_p[i] >= 1) count_ge1++;
        if (man_p[i] >= 2) count_ge2++;
    }

    /* n=6, count_ge1=7, count_ge2=3 => 0x060703 */
    g_result = ((uint32_t)6          << 16)
             | ((uint32_t)count_ge1  <<  8)
             | (uint32_t)count_ge2;
    while (1) {}
}
