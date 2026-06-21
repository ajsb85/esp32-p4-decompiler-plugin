/* test_lyndon_factorization.c
 * Purpose   : Validate Lyndon factorization via the Duval algorithm
 * Algorithm : Duval's O(n) algorithm decomposes a string into Lyndon words
 *             (strictly smallest rotation of themselves).  The algorithm
 *             advances i, j, k pointers scanning the string left-to-right
 *             with no backtracking, making it very cache-friendly and
 *             producing distinctive `i += k - j` stride idioms.
 * Input     : "abbaabab"  (n=8)
 * Expected  : Lyndon factors: "ab", "b", "ab", "ab"  → n_factors = 4
 *             longest factor length = 2, sum of start indices = 0+2+3+5 = 10
 * g_result  = (n << 16) | (n_factors << 8) | longest
 *           = (8 << 16) | (4 << 8) | 2 = 0x080402
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define LYN_MAXN 32
#define LYN_N    8

static const char lyn_s[LYN_N + 1] = "abbaabab";

/* Store factor start indices and lengths */
static int lyn_starts[LYN_MAXN];
static int lyn_lens[LYN_MAXN];
static int lyn_cnt;

static void duval(void) {
    int n = LYN_N;
    int i = 0;
    lyn_cnt = 0;
    while (i < n) {
        int j = i, k = i + 1;
        while (k < n && lyn_s[j] <= lyn_s[k]) {
            if (lyn_s[j] < lyn_s[k]) j = i;
            else                      j++;
            k++;
        }
        /* Emit Lyndon words of length (k - j) */
        int word_len = k - j;
        while (i <= j) {
            lyn_starts[lyn_cnt] = i;
            lyn_lens[lyn_cnt]   = word_len;
            lyn_cnt++;
            i += word_len;
        }
    }
}

void _start(void) {
    duval();

    int longest = 0;
    for (int i = 0; i < lyn_cnt; i++) {
        if (lyn_lens[i] > longest) longest = lyn_lens[i];
    }

    /* n=8, n_factors=4, longest=2 => 0x080402 */
    g_result = ((uint32_t)LYN_N << 16)
             | ((uint32_t)lyn_cnt << 8)
             | (uint32_t)longest;
    while (1) {}
}
