/* test_catalan_triangle.c
 * Purpose   : Compute the Catalan triangle (ballot problem triangle)
 * Algorithm : The Catalan triangle T(n,k) satisfies:
 *               T(n, 0) = 1  for all n >= 0
 *               T(n, k) = T(n, k-1) + T(n-1, k)  for 1 <= k <= n
 *             Row sums equal the Catalan numbers shifted: sum of row n = C(n+1)
 *             (Catalan numbers: 1,1,2,5,14,42,132,429,...)
 * Input     : rows 0..6, n_tests = 7
 * Expected  : Row sums: 1, 2, 5, 14, 42, 132, 429 → grand total = 625
 *             grand_total mod 256 = 625 mod 256 = 113 = 0x71
 *             max entry in row 5 = T(5,5) = 42 = 0x2A
 *             n_tests = 7
 * g_result  = (n_tests<<16) | (grand_total_mod<<8) | max_row5
 *           = (7<<16) | (113<<8) | 42
 *           = 0x07712A
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* Catalan triangle stored row by row; rows 0..6, up to 7 entries each */
static uint32_t cat_tri[7][7];

static void build_catalan_triangle(void) {
    uint32_t n, k;
    for (n = 0u; n < 7u; n++) {
        cat_tri[n][0] = 1u;
        for (k = 1u; k <= n; k++) {
            cat_tri[n][k] = cat_tri[n][k - 1u] + cat_tri[n - 1u][k];
        }
    }
}

void _start(void) {
    uint32_t n_tests = 7u;  /* rows 0..6 */
    build_catalan_triangle();

    uint32_t grand_total = 0u;
    uint32_t n, k;
    for (n = 0u; n < n_tests; n++) {
        for (k = 0u; k <= n; k++) {
            grand_total += cat_tri[n][k];
        }
    }

    uint32_t grand_total_mod = grand_total & 0xFFu;  /* 625 mod 256 = 113 */
    uint32_t max_row5 = cat_tri[5][5];               /* = 42 */

    /* n_tests=7=0x07, grand_total_mod=113=0x71, max_row5=42=0x2A => 0x07712A */
    g_result = (n_tests << 16) | (grand_total_mod << 8) | max_row5;
    while (1) {}
}
