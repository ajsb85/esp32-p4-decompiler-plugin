/* test_sqrt_decomposition.c
 * Purpose   : Validate sqrt-decomposition for range-sum queries with point updates
 * Algorithm : Divide array of n elements into blocks of size B = floor(sqrt(n)).
 *             Maintain block_sum[b] = sum of elements in block b.
 *             Point update: O(1) — update element and its block sum.
 *             Range query [l, r]: O(sqrt(n)) — partial left block + full middle
 *             blocks + partial right block.  Characteristic idioms: integer
 *             square root, block index `i/B`, partial-block loops at boundaries.
 * Input     : arr = {1,2,3,4,5,6,7,8,9,10}, n=10, B=3
 *             Query [2, 7] → sum = 3+4+5+6+7+8 = 33
 *             Update: arr[4] += 5  (arr[4]: 5→10)
 *             Query [2, 7] after update → sum = 3+4+10+6+7+8 = 38
 * g_result  = (n << 16) | (sum1 - 20 << 8) | (sum2 - 30)
 *           = (10 << 16) | (13 << 8) | 8 = 0x0A0D08
 */

#include <stdint.h>

volatile uint32_t g_result;

#define SQD_N  10
#define SQD_B  3   /* block size = ceil(sqrt(10)) = 4, but 3 is sufficient */

static int sqd_arr[SQD_N]     = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
static int sqd_bsum[4]        = {0, 0, 0, 0}; /* block sums; 4 blocks for N=10,B=3 */

static void sqd_build(void) {
    for (int i = 0; i < SQD_N; i++)
        sqd_bsum[i / SQD_B] += sqd_arr[i];
}

static void sqd_update(int idx, int delta) {
    sqd_arr[idx]        += delta;
    sqd_bsum[idx / SQD_B] += delta;
}

static int sqd_query(int l, int r) {
    int sum   = 0;
    int bl    = l / SQD_B;
    int br    = r / SQD_B;
    if (bl == br) {
        for (int i = l; i <= r; i++) sum += sqd_arr[i];
    } else {
        /* Partial left block */
        int left_end = (bl + 1) * SQD_B - 1;
        for (int i = l; i <= left_end; i++) sum += sqd_arr[i];
        /* Full middle blocks */
        for (int b = bl + 1; b < br; b++) sum += sqd_bsum[b];
        /* Partial right block */
        int right_start = br * SQD_B;
        for (int i = right_start; i <= r; i++) sum += sqd_arr[i];
    }
    return sum;
}

void _start(void) {
    sqd_build();

    int sum1 = sqd_query(2, 7);  /* 3+4+5+6+7+8 = 33 */

    sqd_update(4, 5);            /* arr[4]: 5 → 10 */

    int sum2 = sqd_query(2, 7);  /* 3+4+10+6+7+8 = 38 */

    /* n=10, sum1-20=13, sum2-30=8 => 0x0A0D08 */
    g_result = ((uint32_t)SQD_N        << 16)
             | ((uint32_t)(sum1 - 20)  <<  8)
             | (uint32_t)(sum2 - 30);
    while (1) {}
}
