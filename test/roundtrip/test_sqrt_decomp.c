/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Square-Root Decomposition (range sum) fixture.
 *
 * Divides an array of n elements into blocks of size ⌈√n⌉.
 * Precomputes a block sum for each block. Operations:
 *   Point update: O(1) — update arr[i] and its block sum.
 *   Range query  [l,r]: O(√n) — sum partial left block + full blocks + partial right block.
 *
 * Distinctive decompiler idioms:
 *   1. `block[i/block_sz] += arr[i]` — build phase
 *   2. `block[i/block_sz] += val - arr[i]; arr[i] = val` — point update
 *   3. Range query loop separating partial-left, full, partial-right blocks
 *
 * Array: {1,2,3,4,5,6,7,8,9}  (n=9, block_sz=3)
 * Blocks: B[0]=6, B[1]=15, B[2]=24
 *
 * Operations:
 *   query [2..7]  before update → {3}+{15}+{7+8} = 33
 *   point update arr[4] = 10   → B[1] becomes 20
 *   query [1..8]  after  update → {2+3}+{20}+{7+8+9} = 49
 *
 * n        = 9
 * sum1     = 33  (0x21)
 * sum2     = 49  (0x31)
 *
 * g_result = (9 << 16) | (33 << 8) | 49 = 0x00092131
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SQ_N  9
#define SQ_BS 3   /* block size = sqrt(9) = 3 */
#define SQ_NB 3   /* number of blocks */

static int sq_arr[SQ_N];
static int sq_blk[SQ_NB];

static void sq_update(int idx, int val)
{
    sq_blk[idx / SQ_BS] += val - sq_arr[idx];
    sq_arr[idx] = val;
}

static int sq_query(int l, int r)
{
    int sum = 0;
    int bl = l / SQ_BS, br = r / SQ_BS;
    if (bl == br) {
        /* same block — iterate elements */
        for (int i = l; i <= r; i++) sum += sq_arr[i];
    } else {
        /* partial left block */
        for (int i = l; i < (bl + 1) * SQ_BS; i++) sum += sq_arr[i];
        /* full blocks in between */
        for (int b = bl + 1; b < br; b++) sum += sq_blk[b];
        /* partial right block */
        for (int i = br * SQ_BS; i <= r; i++) sum += sq_arr[i];
    }
    return sum;
}

void test_sqrt_decomp(void)
{
    static const int init[SQ_N] = {1,2,3,4,5,6,7,8,9};
    for (int i = 0; i < SQ_N; i++) {
        sq_arr[i] = init[i];
        sq_blk[i / SQ_BS] += init[i];
    }

    int sum1 = sq_query(2, 7); /* 33: arr[2..7]={3,4,5,6,7,8} */

    sq_update(4, 10);          /* arr[4] was 5, now 10; B[1]: 15→20 */

    int sum2 = sq_query(1, 8); /* 49: arr[1..8]={2,3,4,10,6,7,8,9} */

    /* sum1=33, sum2=49 */
    g_result = ((uint32_t)SQ_N << 16)
             | ((uint32_t)(sum1 & 0xFF) << 8)
             | (uint32_t)(sum2 & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_sqrt_decomp();
    for (;;);
}
