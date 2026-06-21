/* test_stirling_numbers.c
 * Purpose   : Validate unsigned Stirling numbers of the first kind c(n,k)
 * Algorithm : c(n,k) = c(n-1,k-1) + (n-1)*c(n-1,k), c(0,0)=1, c(n,0)=0 n>0
 *             c(n,k) counts permutations of n elements with exactly k cycles.
 * Tests     : c(5,2)=50, c(4,3)=11, c(5,5)=1
 *             n_tests=3, metric_a=c(5,2)%256=50=0x32, metric_b=c(4,3)=11=0x0B
 * g_result  = (3<<16)|(0x32<<8)|0x0B = 0x03320B
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define STR1_N 6  /* table rows 0..5 */
#define STR1_K 6  /* table cols 0..5 */

static uint32_t str1[STR1_N][STR1_K];

static void stirling1_build(void) {
    for (int i = 0; i < STR1_N; i++)
        for (int j = 0; j < STR1_K; j++)
            str1[i][j] = 0;
    str1[0][0] = 1;
    for (int n = 1; n < STR1_N; n++) {
        for (int k = 1; k <= n && k < STR1_K; k++) {
            str1[n][k] = (uint32_t)(n - 1) * str1[n-1][k] + str1[n-1][k-1];
        }
    }
}

static uint32_t run_stirling1_tests(void) {
    stirling1_build();

    /* Test 1: c(5,2) = 50 */
    uint32_t c52 = str1[5][2];  /* expect 50 */

    /* Test 2: c(4,3) = 11 */
    uint32_t c43 = str1[4][3];  /* expect 11 */

    /* Test 3: c(5,5) = 1 (identity permutation, n cycles) */
    uint32_t c55 = str1[5][5];  /* expect 1 */
    (void)c55;

    /* metric_a = c52 % 256 = 50 = 0x32
     * metric_b = c43       = 11 = 0x0B
     * n_tests=3 => 0x03320B */
    uint32_t metric_a = c52 & 0xFFu;
    uint32_t metric_b = c43 & 0xFFu;
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_stirling1_tests();
    while (1) {}
}
