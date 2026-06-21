/*
 * test_count_distinct_substrings.c
 * Count Distinct Substrings using a Suffix Array + LCP Array approach.
 * Total distinct substrings = n*(n+1)/2 - sum(LCP[i]) for i=1..n-1,
 * where n = string length, LCP is the LCP array of the suffix array.
 *
 * Suffix array built with O(n log^2 n) prefix doubling.
 * LCP array computed with Kasai's O(n) algorithm.
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CDS_MAXN 32

/* Suffix array by prefix doubling */
static int32_t sa[CDS_MAXN], rk[CDS_MAXN], tmp[CDS_MAXN];
static int32_t lcp[CDS_MAXN];

/* Comparison uses rank array rk and half-period gap */
static int32_t cds_gap;
static const char *cds_str;
static int32_t cds_n;

static int cds_cmp(int32_t a, int32_t b) {
    if (rk[a] != rk[b]) return (rk[a] < rk[b]) ? -1 : 1;
    int32_t ra = (a + cds_gap < cds_n) ? rk[a + cds_gap] : -1;
    int32_t rb = (b + cds_gap < cds_n) ? rk[b + cds_gap] : -1;
    return (ra < rb) ? -1 : (ra > rb) ? 1 : 0;
}

/* Simple insertion sort for small n */
static void cds_sort(void) {
    for (int i = 1; i < cds_n; i++) {
        int32_t key = sa[i];
        int j = i - 1;
        while (j >= 0 && cds_cmp(sa[j], key) > 0) {
            sa[j + 1] = sa[j];
            j--;
        }
        sa[j + 1] = key;
    }
}

static void build_sa(const char *s, int32_t n) {
    cds_str = s;
    cds_n   = n;
    for (int i = 0; i < n; i++) { sa[i] = i; rk[i] = (int32_t)(unsigned char)s[i]; }
    for (cds_gap = 1; cds_gap < n; cds_gap *= 2) {
        cds_sort();
        tmp[sa[0]] = 0;
        for (int i = 1; i < n; i++)
            tmp[sa[i]] = tmp[sa[i-1]] + (cds_cmp(sa[i], sa[i-1]) != 0 ? 1 : 0);
        for (int i = 0; i < n; i++) rk[i] = tmp[i];
        if (rk[sa[n-1]] == n - 1) break; /* all ranks distinct */
    }
}

/* Kasai's LCP algorithm */
static int32_t inv_sa[CDS_MAXN];

static void build_lcp(const char *s, int32_t n) {
    for (int i = 0; i < n; i++) inv_sa[sa[i]] = i;
    int32_t h = 0;
    lcp[0] = 0;
    for (int i = 0; i < n; i++) {
        if (inv_sa[i] == 0) { h = 0; continue; }
        int32_t j = sa[inv_sa[i] - 1];
        while (i + h < n && j + h < n && s[i + h] == s[j + h]) h++;
        lcp[inv_sa[i]] = h;
        if (h > 0) h--;
    }
}

static uint32_t count_distinct(int32_t n) {
    uint32_t total = (uint32_t)n * (uint32_t)(n + 1) / 2;
    for (int i = 1; i < n; i++) total -= (uint32_t)lcp[i];
    return total;
}

static uint32_t run_cds_tests(void) {
    /*
     * Test 1: "banana" (length 6).
     * SA = [5,3,1,0,4,2] for "banana".
     * LCP = [0,1,3,0,0,2].
     * Total = 6*7/2 - (1+3+0+0+2) = 21 - 6 = 15.
     */
    const char *s1 = "banana";
    int32_t n1 = 6;
    build_sa(s1, n1);
    build_lcp(s1, n1);
    uint32_t distinct1 = count_distinct(n1); /* 15 */

    /*
     * Test 2: "abab" (length 4).
     * All substrings: a,b,ab,ba,aba,bab,abab,abab,bab — distinct: a,b,ab,ba,aba,bab,abab = 7.
     */
    const char *s2 = "abab";
    int32_t n2 = 4;
    build_sa(s2, n2);
    build_lcp(s2, n2);
    uint32_t distinct2 = count_distinct(n2); /* 7 */

    /*
     * Test 3: "aaa" (length 3).
     * Substrings: a,aa,aaa,a,aa,a — distinct: a,aa,aaa = 3.
     * Total = 3*4/2 - (1+2) = 6 - 3 = 3.
     */
    const char *s3 = "aaa";
    int32_t n3 = 3;
    build_sa(s3, n3);
    build_lcp(s3, n3);
    uint32_t distinct3 = count_distinct(n3); /* 3 */
    (void)distinct3;

    /*
     * Pack: n_tests=3, metric_a = distinct1 = 15 = 0x0F,
     *        metric_b = distinct2 = 7 = 0x07.
     * n=3(0x03), a=15(0x0F), b=7(0x07) — all non-zero, distinct. OK.
     */
    uint32_t metric_a = distinct1 & 0xFF;  /* 15 = 0x0F */
    uint32_t metric_b = distinct2 & 0xFF;  /* 7  = 0x07 */
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_cds_tests();
    while (1) {}
}
