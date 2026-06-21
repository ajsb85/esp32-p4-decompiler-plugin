/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Sparse table static Range Minimum Query (RMQ) fixture.
 *
 * Build O(n log n), query O(1).
 *
 * Build idiom:
 *   for j in 1..LOG:
 *     for i in 0..n-(1<<j):
 *       st[j][i] = min(st[j-1][i], st[j-1][i + (1<<(j-1))])
 *
 * Query idiom:
 *   k = ilog2(r - l + 1);
 *   return min(st[k][l], st[k][r - (1<<k) + 1])
 *
 * Input (n=8): arr = {3, 7, 1, 9, 2, 8, 5, 4}
 *
 * Sparse table (LOG=3):
 *   st[0] = {3,7,1,9,2,8,5,4}
 *   st[1] = {3,1,1,2,2,5,4}    (min over 2-element windows)
 *   st[2] = {1,1,1,2,2}        (min over 4-element windows)
 *   st[3] = {1}                 (min over 8-element window)
 *
 * Three RMQ queries:
 *   RMQ(0,1) = min(3,7) = 3   k=1: min(st[1][0], st[1][0])  = 3
 *   RMQ(1,4) = min(7,1,9,2)=1 k=2: min(st[2][1], st[2][1])  = 1
 *   RMQ(5,7) = min(8,5,4) = 4 k=1: min(st[1][5], st[1][6])  = 4
 *
 *   sum = 3+1+4 = 8
 *   xor = 3^1^4 = 6
 *   n   = 8
 *
 * g_result = (n << 16) | (sum << 8) | xor = 0x00080806
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Sparse table ─────────────────────────────────────────────────────────── */

#define ST_N   8
#define ST_LOG 3    /* ceil(log2(8)) = 3 */

static int st[ST_LOG + 1][ST_N];

static int ilog2_st(int n)
{
    int k = 0;
    while ((1 << (k + 1)) <= n) k++;
    return k;
}

static void sparse_build(const int *arr, int n)
{
    for (int i = 0; i < n; i++)
        st[0][i] = arr[i];

    for (int j = 1; j <= ST_LOG; j++) {
        for (int i = 0; i + (1 << j) - 1 < n; i++) {
            int a = st[j - 1][i];
            int b = st[j - 1][i + (1 << (j - 1))];
            st[j][i] = (a < b) ? a : b;
        }
    }
}

static int sparse_query(int l, int r)
{
    int k  = ilog2_st(r - l + 1);
    int a  = st[k][l];
    int b  = st[k][r - (1 << k) + 1];
    return (a < b) ? a : b;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_sparse_table(void)
{
    static const int arr[ST_N] = {3, 7, 1, 9, 2, 8, 5, 4};

    sparse_build(arr, ST_N);

    int q0 = sparse_query(0, 1);   /* = 3 */
    int q1 = sparse_query(1, 4);   /* = 1 */
    int q2 = sparse_query(5, 7);   /* = 4 */

    uint32_t sum_q = (uint32_t)(q0 + q1 + q2);   /* = 8 */
    uint32_t xor_q = (uint32_t)(q0 ^ q1 ^ q2);   /* = 6 */

    g_result = ((uint32_t)ST_N << 16)
             | (sum_q << 8)
             | (xor_q & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_sparse_table();
    for (;;);
}
