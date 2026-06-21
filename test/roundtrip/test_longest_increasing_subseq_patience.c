/*
 * test_longest_increasing_subseq_patience.c
 * Longest Increasing Subsequence via patience sorting (O(n log n)).
 * Self-contained, no stdlib — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAXN 64

/* Binary search: find leftmost index in tails[0..len) where tails[i] >= val */
static int lis_lower_bound(int *tails, int len, int val) {
    int lo = 0, hi = len;
    while (lo < hi) {
        int mid = (lo + hi) >> 1;
        if (tails[mid] < val)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/* Returns length of LIS of arr[0..n) using patience sort tails array */
static int lis_patience(int *arr, int n) {
    int tails[MAXN];
    int len = 0;
    for (int i = 0; i < n; i++) {
        int pos = lis_lower_bound(tails, len, arr[i]);
        tails[pos] = arr[i];
        if (pos == len)
            len++;
    }
    return len;
}

static uint32_t run_lis_tests(void) {
    /* Test 1: classic example — LIS = 6 */
    int a1[] = {3, 10, 2, 1, 20, 4, 6, 5, 9, 7};
    int n1 = 10;
    int r1 = lis_patience(a1, n1); /* expected 5: 1,4,6,7 or similar — actually 5 */

    /* Test 2: strictly increasing — LIS = length */
    int a2[] = {1, 2, 3, 4, 5, 6, 7, 8};
    int n2 = 8;
    int r2 = lis_patience(a2, n2); /* expected 8 */

    /* Test 3: strictly decreasing — LIS = 1 */
    int a3[] = {9, 8, 7, 6, 5, 4, 3, 2, 1};
    int n3 = 9;
    int r3 = lis_patience(a3, n3); /* expected 1 */

    /* Pack: n_tests=3, metric_a=r1+r2 (=13 → 0x0D), metric_b=r3 */
    uint32_t metric_a = (uint32_t)(r1 + r2); /* 5+8 = 13 = 0x0D */
    uint32_t metric_b = (uint32_t)r3;        /* 1   = 0x01 */
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_lis_tests();
    while (1) {}
}
