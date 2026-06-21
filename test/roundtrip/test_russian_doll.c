#include <stdint.h>

/* Russian Doll Envelopes: find max nesting of envelopes (w1<w2 && h1<h2).
 * Sort by width ascending; for equal widths sort height descending
 * (prevents using two same-width envelopes in a valid sequence).
 * Then find LIS on heights using patience sort (O(n log n)).
 * g_result encodes (n_tests, sum_results, xor_results). */

typedef struct { int w; int h; } Env;

static void sort_envs(Env *e, int n) {
    int i, j;
    for (i = 1; i < n; i++) {
        Env key = e[i];
        j = i - 1;
        while (j >= 0 && (e[j].w > key.w ||
                          (e[j].w == key.w && e[j].h < key.h))) {
            e[j + 1] = e[j];
            j--;
        }
        e[j + 1] = key;
    }
}

static int lis_heights(const Env *e, int n) {
    int tails[8];
    int sz = 0;
    int i, lo, hi, mid;
    for (i = 0; i < n; i++) {
        lo = 0; hi = sz;
        while (lo < hi) {
            mid = (lo + hi) / 2;
            if (tails[mid] < e[i].h) lo = mid + 1;
            else hi = mid;
        }
        tails[lo] = e[i].h;
        if (lo == sz) sz++;
    }
    return sz;
}

volatile uint32_t g_result;

void test_russian_doll(void) {
    Env e1[] = {{2,3},{5,4},{6,4},{6,7},{1,1}};
    Env e2[] = {{1,1},{1,1},{1,1}};
    Env e3[] = {{4,6},{3,5},{2,4},{1,3}};
    sort_envs(e1, 5);
    sort_envs(e2, 3);
    sort_envs(e3, 4);
    int r1 = lis_heights(e1, 5); /* 4 */
    int r2 = lis_heights(e2, 3); /* 1 */
    int r3 = lis_heights(e3, 4); /* 4 */
    int s = r1 + r2 + r3;        /* 9 */
    int x = r1 ^ r2 ^ r3;        /* 1 */
    g_result = (3u << 16) | ((uint32_t)s << 8) | (uint32_t)x; /* 0x00030901 */
}

__attribute__((noreturn)) void _start(void) {
    test_russian_doll();
    for (;;);
}
