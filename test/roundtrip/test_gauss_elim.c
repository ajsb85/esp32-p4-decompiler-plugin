/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Gaussian Elimination fixture.
 *
 * Solves a 3×3 system Ax = b via Gaussian elimination with partial pivoting.
 * Uses only integer arithmetic (coefficients scaled to avoid fractions).
 *
 * System:
 *   2x + y - z = 8   [row 0]
 *  -3x - y + 2z = -11 [row 1]
 *  -2x + y + 2z = -3  [row 2]
 *
 * Solution: x=2, y=3, z=-1
 *
 * Distinctive decompiler idioms:
 *   1. Partial pivot swap: `for (k=i+1; ...) if (|a[k][i]|>|a[max][i]|) max=k`
 *   2. Elimination: `a[j][k] -= (a[j][i]*a[i][k]) / a[i][i]` (integer scaling)
 *   3. Back-substitution: `x[i] = (b[i] - Σ a[i][k]*x[k]) / a[i][i]`
 *   4. Row-swap idiom: `swap(a[i], a[max])` for augmented matrix rows
 *
 * Note: to keep integer arithmetic exact, this implementation uses an
 * augmented integer matrix and rational-free elimination via scaling.
 * We track the denominator separately (GCD-reduced) to avoid fractions.
 *
 * Simpler approach: work with integer multiples. Eliminate without division
 * by cross-multiplying:
 *   row_j = row_j * a[i][i] - row_i * a[j][i]
 *   (GCD-reduce each row to prevent overflow)
 *
 * Solution: x=2, y=3, z=-1 → encoded as x_pos=2, y_pos=3, z_neg=1
 *
 * g_result = (x_val << 16) | (y_val << 8) | (-z_val) = 0x020301
 */
#include <stdint.h>

volatile uint32_t g_result;

#define GE_N 3

static int ge_a[GE_N][GE_N + 1];  /* augmented [A|b] */

static int ge_abs(int x) { return x < 0 ? -x : x; }

static int ge_gcd(int a, int b)
{
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    while (b) { int t = b; b = a % b; a = t; }
    return a;
}

static void ge_reduce_row(int r)
{
    int g = 0;
    for (int c = 0; c <= GE_N; c++) g = ge_gcd(g, ge_abs(ge_a[r][c]));
    if (g > 1) for (int c = 0; c <= GE_N; c++) ge_a[r][c] /= g;
}

/* Returns the solved variable values (multiplied by denominator, but here
 * the system is designed so all values are exact integers). */
static void gauss_elim(int *sol)
{
    /* Forward elimination with partial pivoting */
    for (int i = 0; i < GE_N; i++) {
        /* Find pivot */
        int max_row = i;
        for (int k = i + 1; k < GE_N; k++)
            if (ge_abs(ge_a[k][i]) > ge_abs(ge_a[max_row][i])) max_row = k;

        /* Swap rows */
        for (int c = 0; c <= GE_N; c++) {
            int t = ge_a[i][c]; ge_a[i][c] = ge_a[max_row][c]; ge_a[max_row][c] = t;
        }

        /* Eliminate below pivot using cross-multiply to stay integer */
        for (int j = i + 1; j < GE_N; j++) {
            int factor = ge_a[j][i];
            int pivot  = ge_a[i][i];
            for (int c = 0; c <= GE_N; c++)
                ge_a[j][c] = ge_a[j][c] * pivot - factor * ge_a[i][c];
            ge_reduce_row(j);
        }
    }

    /* Back-substitution */
    for (int i = GE_N - 1; i >= 0; i--) {
        int val = ge_a[i][GE_N];
        for (int c = i + 1; c < GE_N; c++) val -= ge_a[i][c] * sol[c];
        sol[i] = val / ge_a[i][i];
    }
}

void test_gauss_elim(void)
{
    static const int mat[GE_N][GE_N + 1] = {
        { 2,  1, -1,   8},
        {-3, -1,  2, -11},
        {-2,  1,  2,  -3},
    };

    /* Copy to working array */
    for (int i = 0; i < GE_N; i++)
        for (int j = 0; j <= GE_N; j++)
            ge_a[i][j] = mat[i][j];

    int sol[GE_N] = {0};
    gauss_elim(sol);
    /* sol = {2, 3, -1} */

    g_result = ((uint32_t)sol[0]     << 16)
             | ((uint32_t)sol[1]     << 8)
             | ((uint32_t)(-sol[2]) & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_gauss_elim();
    for (;;);
}
