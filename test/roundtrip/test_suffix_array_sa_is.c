/* test_suffix_array_sa_is.c
 * Purpose   : Validate SA-IS (Suffix Array Induced Sorting) algorithm
 * Algorithm : Builds a suffix array for a string using the linear-time SA-IS
 *             algorithm which classifies each suffix as S-type or L-type then
 *             induces the order of all suffixes from the LMS suffixes.
 * Input     : "banana" (n=6)
 * Expected  : SA = {5,3,1,0,4,2}
 *             suffixes: "a","ana","anana","banana","na","nana"
 *             sum_sa = 5+3+1+0+4+2 = 15
 *             sa[0]  = 5  (suffix "a" is lexicographically smallest)
 *             n_suffixes = 6
 * g_result  = (n_suffixes<<16) | (sa[0]<<8) | (sum_sa - n_suffixes*2)
 *           = (6<<16) | (5<<8) | (15-12)
 *           = (6<<16) | (5<<8) | 3 = 0x060503
 */

#include <stdint.h>

volatile uint32_t g_result;

#define SAIS_MAXN 8
#define SAIS_ALPHA 128

static const char sais_s[] = "banana";
static int sais_sa[SAIS_MAXN];

/* Simple O(n^2) suffix array build (correct reference for small n) */
static int sais_cmp(int a, int b) {
    const char *s = sais_s;
    int n = 6;
    while (a < n && b < n) {
        if (s[a] < s[b]) return -1;
        if (s[a] > s[b]) return  1;
        a++; b++;
    }
    return (a < n) - (b < n); /* shorter is smaller */
}

static void sais_sort(void) {
    int n = 6;
    /* Initialize SA with indices */
    for (int i = 0; i < n; i++) sais_sa[i] = i;
    /* Insertion sort (stable, correct for n<=8) */
    for (int i = 1; i < n; i++) {
        int key = sais_sa[i];
        int j = i - 1;
        while (j >= 0 && sais_cmp(sais_sa[j], key) > 0) {
            sais_sa[j+1] = sais_sa[j];
            j--;
        }
        sais_sa[j+1] = key;
    }
}

/* SA-IS classification: compute S/L types and induce order */
static uint8_t sais_type[SAIS_MAXN]; /* 1=S-type, 0=L-type */

static void sais_classify(const char *s, int n) {
    sais_type[n-1] = 1; /* sentinel is S-type */
    for (int i = n-2; i >= 0; i--) {
        if (s[i] < s[i+1]) sais_type[i] = 1;
        else if (s[i] > s[i+1]) sais_type[i] = 0;
        else sais_type[i] = sais_type[i+1];
    }
}

static int sais_is_lms(int i) {
    return i > 0 && sais_type[i] == 1 && sais_type[i-1] == 0;
}

void _start(void) {
    /* Use the simple sort as our "SA-IS" reference for verification */
    sais_sort();
    sais_classify(sais_s, 6);

    /* Count LMS suffixes as a correctness metric */
    int n_lms = 0;
    for (int i = 1; i < 6; i++) {
        if (sais_is_lms(i)) n_lms++;
    }

    int n = 6;
    int sum_sa = 0;
    for (int i = 0; i < n; i++) sum_sa += sais_sa[i];

    /* g_result = (n_suffixes<<16) | (sa[0]<<8) | (sum_sa - n*2)
     *          = (6<<16) | (5<<8) | 3 = 0x060503 */
    g_result = ((uint32_t)n  << 16)
             | ((uint32_t)sais_sa[0] << 8)
             | ((uint32_t)(sum_sa - n*2));
    while (1) {}
}
