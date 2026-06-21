#include <stdint.h>

/* Minimum cuts to partition a string into palindromic substrings.
 * Precompute pal[i][j]=1 if s[i..j] is a palindrome (bottom-up by length).
 * cuts[i] = min cuts for s[0..i]; 0 if s[0..i] itself is a palindrome.
 * g_result encodes (n_tests, total_char_count, sum_min_cuts). */

#define MAX_L 8

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }

static int min_pal_cuts(const char *s) {
    int n = slen(s);
    int pal[MAX_L][MAX_L];
    int cuts[MAX_L];
    int i, j, len;
    for (i = 0; i < n; i++)
        for (j = 0; j < n; j++)
            pal[i][j] = 0;
    for (i = 0; i < n; i++) pal[i][i] = 1;
    for (i = 0; i + 1 < n; i++) pal[i][i + 1] = (s[i] == s[i + 1]);
    for (len = 3; len <= n; len++)
        for (i = 0; i + len - 1 < n; i++) {
            j = i + len - 1;
            pal[i][j] = (s[i] == s[j]) && pal[i + 1][j - 1];
        }
    for (i = 0; i < n; i++) {
        if (pal[0][i]) { cuts[i] = 0; continue; }
        cuts[i] = i;
        for (j = 1; j <= i; j++)
            if (pal[j][i] && cuts[j - 1] + 1 < cuts[i])
                cuts[i] = cuts[j - 1] + 1;
    }
    return cuts[n - 1];
}

volatile uint32_t g_result;

void test_palindrome_partition2(void) {
    int r1 = min_pal_cuts("aab");   /* 1: ["aa","b"]         */
    int r2 = min_pal_cuts("aaaa");  /* 0: whole is palindrome */
    int r3 = min_pal_cuts("abc");   /* 2: ["a","b","c"]      */
    int total_len = 3 + 4 + 3;      /* 10 */
    int sum_cuts  = r1 + r2 + r3;   /* 3  */
    g_result = (3u << 16) |
               ((uint32_t)total_len << 8) |
               (uint32_t)sum_cuts; /* 0x00030A03 */
}

__attribute__((noreturn)) void _start(void) {
    test_palindrome_partition2();
    for (;;);
}
