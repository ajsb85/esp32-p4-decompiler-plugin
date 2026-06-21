/* test_sparse_table.c
 * Purpose   : Validate sparse table for static range minimum query (RMQ)
 * Algorithm : Build sparse table in O(n log n) using doubling.
 *             Answer RMQ(l,r) in O(1) via two overlapping power-of-two ranges.
 * Input     : arr = {3,1,4,1,5,9,2,6}  (n=8, classic digits-of-pi prefix)
 * Queries   : RMQ(0,7)=1, RMQ(4,7)=2, RMQ(2,5)=1  (3 queries, sum=4)
 * Expected  : n=8, n_queries=3, sum_results=4
 * g_result  = (n << 16) | (n_queries << 8) | sum_results
 *           = (8 << 16) | (3 << 8) | 4 = 0x080304
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define ST_N    8
#define ST_LOG  4   /* 2^3 == 8 so k in [0,3], need 4 rows */

static const int st_arr[ST_N] = {3, 1, 4, 1, 5, 9, 2, 6};
static int st_table[ST_LOG][ST_N];
static int st_log2[ST_N + 1]; /* floor(log2(i)) for i in [1..ST_N] */

static void st_build(void) {
    st_log2[1] = 0;
    for (int i = 2; i <= ST_N; i++) st_log2[i] = st_log2[i / 2] + 1;

    for (int i = 0; i < ST_N; i++) st_table[0][i] = st_arr[i];

    for (int k = 1; (1 << k) <= ST_N; k++) {
        int half = 1 << (k - 1);
        for (int i = 0; i + (1 << k) - 1 < ST_N; i++) {
            int a = st_table[k-1][i];
            int b = st_table[k-1][i + half];
            st_table[k][i] = (a < b) ? a : b;
        }
    }
}

static int st_rmq(int l, int r) {
    int k = st_log2[r - l + 1];
    int a = st_table[k][l];
    int b = st_table[k][r - (1 << k) + 1];
    return (a < b) ? a : b;
}

void _start(void) {
    st_build();

    int sum = 0;
    sum += st_rmq(0, 7); /* min(3,1,4,1,5,9,2,6) = 1 */
    sum += st_rmq(4, 7); /* min(5,9,2,6) = 2           */
    sum += st_rmq(2, 5); /* min(4,1,5,9) = 1           */

    g_result = ((uint32_t)ST_N << 16) | (3u << 8) | (uint32_t)sum;
    while (1) {}
}
