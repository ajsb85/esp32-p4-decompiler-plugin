#include <stdint.h>

/* Maximum sum of a circular subarray.
 * Key insight: max_circular = max(kadane_max, total_sum - kadane_min).
 * All-negative guard: if total - min_sub == 0 (all negative) return max_sub.
 * g_result encodes (n_tests, sum_positive_results, count_positive). */

static int imax(int a, int b) { return a > b ? a : b; }
static int imin(int a, int b) { return a < b ? a : b; }

static int kadane_max(int *a, int n) {
    int cur = a[0], mx = a[0];
    for (int i = 1; i < n; i++) {
        cur = imax(a[i], cur + a[i]);
        mx  = imax(mx, cur);
    }
    return mx;
}

static int kadane_min(int *a, int n) {
    int cur = a[0], mn = a[0];
    for (int i = 1; i < n; i++) {
        cur = imin(a[i], cur + a[i]);
        mn  = imin(mn, cur);
    }
    return mn;
}

static int max_circular(int *a, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += a[i];
    int mx = kadane_max(a, n);
    int mn = kadane_min(a, n);
    return (total - mn > 0) ? imax(mx, total - mn) : mx;
}

volatile uint32_t g_result;

void test_max_circular_subarray(void) {
    int a1[] = {1, -2, 3, -2};      int r1 = max_circular(a1, 4); /* 3  */
    int a2[] = {5, -3, 5};          int r2 = max_circular(a2, 3); /* 10 */
    int a3[] = {-3, -1, -2};        int r3 = max_circular(a3, 3); /* -1 */

    int sp = 0, cp = 0;
    if (r1 > 0) { sp += r1; cp++; }
    if (r2 > 0) { sp += r2; cp++; }
    if (r3 > 0) { sp += r3; cp++; }
    /* sp=13, cp=2 → g=0x00030D02 */
    g_result = (3u << 16) | ((uint32_t)sp << 8) | (uint32_t)cp;
}

__attribute__((noreturn)) void _start(void) {
    test_max_circular_subarray();
    for (;;);
}
