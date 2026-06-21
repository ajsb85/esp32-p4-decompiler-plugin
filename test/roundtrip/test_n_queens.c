/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — N-Queens Backtracking fixture.
 *
 * Count solutions to the N-Queens problem: place N queens on an NxN board
 * such that no two queens threaten each other.
 *
 * Backtracking with three boolean arrays:
 *   col_used[c]           — column c is occupied
 *   diag1[row+col]        — "/" diagonal is occupied
 *   diag2[row-col+n-1]    — "\" diagonal is occupied
 *
 * Distinctive decompiler idioms:
 *   1. Three simultaneous set/unset: col/diag1/diag2 all set then cleared
 *   2. Recursive row-by-row placement
 *   3. `row - col + n - 1` diagonal index (signed-to-unsigned shift trick)
 *
 * Solutions:
 *   N=4: 2    N=5: 10    N=6: 4
 *
 * n_max    = 6
 * sum      = 2+10+4 = 16  (0x10)
 * xor      = 2^10^4 = 12  (0x0C)
 *
 * g_result = (n_max << 16) | (sum << 8) | xor = 0x0006100C
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── N-Queens ─────────────────────────────────────────────────────────────── */

#define NQ_MAX 6

static int nq_col[NQ_MAX];
static int nq_d1[NQ_MAX * 2];   /* "/" diagonals */
static int nq_d2[NQ_MAX * 2];   /* "\" diagonals */
static int nq_count;

static void nq_solve(int row, int n)
{
    if (row == n) { nq_count++; return; }
    for (int c = 0; c < n; c++) {
        int d1 = row + c;
        int d2 = row - c + n - 1;
        if (!nq_col[c] && !nq_d1[d1] && !nq_d2[d2]) {
            nq_col[c] = nq_d1[d1] = nq_d2[d2] = 1;
            nq_solve(row + 1, n);
            nq_col[c] = nq_d1[d1] = nq_d2[d2] = 0;
        }
    }
}

static int n_queens(int n)
{
    for (int i = 0; i < n;     i++) nq_col[i] = 0;
    for (int i = 0; i < 2*n;   i++) nq_d1[i] = nq_d2[i] = 0;
    nq_count = 0;
    nq_solve(0, n);
    return nq_count;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_n_queens(void)
{
    int s4 = n_queens(4);   /* 2  */
    int s5 = n_queens(5);   /* 10 */
    int s6 = n_queens(6);   /* 4  */

    uint32_t sum_s = (uint32_t)(s4 + s5 + s6);
    uint32_t xor_s = (uint32_t)(s4 ^ s5 ^ s6);
    /* sum=16, xor=12 */

    g_result = ((uint32_t)NQ_MAX << 16) | (sum_s << 8) | (xor_s & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_n_queens();
    for (;;);
}
