/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Matrix Fast Exponentiation (Fibonacci via mat-pow) fixture.
 *
 * The n-th Fibonacci number can be computed in O(log n) using the identity:
 *   [[1,1],[1,0]]^n = [[F(n+1), F(n)],[F(n), F(n-1)]]
 *
 * Matrix fast exponentiation:
 *   result = identity; base = fib_matrix
 *   while n > 0:
 *       if n % 2 == 1: result = result * base
 *       base = base * base
 *       n >>= 1
 *
 * Distinctive decompiler idioms:
 *   1. `C[i][j] = Σ A[i][k]*B[k][j]` — 2×2 matrix multiply
 *   2. `if n%2==1: result = result*base` — odd-exponent branch
 *   3. `base = base*base; n>>=1` — square-and-halve loop
 *   4. `R[0][0]=R[1][1]=1; R[0][1]=R[1][0]=0` — identity init
 *
 * Computes F(10)=55, F(20)=6765.
 * Low byte of each: 55, 6765&0xFF=109.
 *
 * n_tests = 2
 * sum     = 55+109 = 164 = 0xA4
 * xor     = 55^109 = 90  = 0x5A
 *
 * g_result = (n_tests << 16) | (sum << 8) | xor = 0x0002A45A
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── 2×2 long long matrix type ───────────────────────────────────────────────── */

typedef struct {
    long long v[2][2];
} Mat22;

/* ── 2×2 matrix multiply ─────────────────────────────────────────────────────── */

static Mat22 mat_mul22(Mat22 A, Mat22 B)
{
    Mat22 C;
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 2; j++) {
            C.v[i][j] = 0;
            for (int k = 0; k < 2; k++)
                C.v[i][j] += A.v[i][k] * B.v[k][j];
        }
    return C;
}

/* ── Matrix fast exponentiation ─────────────────────────────────────────────── */

static Mat22 mat_pow22(Mat22 base, int n)
{
    Mat22 result;
    result.v[0][0] = result.v[1][1] = 1;
    result.v[0][1] = result.v[1][0] = 0; /* identity */
    while (n > 0) {
        if (n % 2 == 1) result = mat_mul22(result, base);
        base = mat_mul22(base, base);
        n /= 2;
    }
    return result;
}

/* ── Test entry point ────────────────────────────────────────────────────────── */

void test_matrix_power(void)
{
    /* Fibonacci base matrix [[1,1],[1,0]] */
    Mat22 fib_base;
    fib_base.v[0][0] = fib_base.v[0][1] = fib_base.v[1][0] = 1;
    fib_base.v[1][1] = 0;

    /* [[1,1],[1,0]]^n [0][1] = F(n) */
    Mat22 r10 = mat_pow22(fib_base, 10); /* F(10)=55  */
    Mat22 r20 = mat_pow22(fib_base, 20); /* F(20)=6765 */

    int f10 = (int)r10.v[0][1]; /* 55   */
    int f20 = (int)r20.v[0][1]; /* 6765 */

    uint32_t sum     = (uint32_t)((f10 & 0xFF) + (f20 & 0xFF)); /* 55+109=164 */
    uint32_t xor_val = (uint32_t)((f10 & 0xFF) ^ (f20 & 0xFF)); /* 55^109=90  */

    g_result = (2u << 16) | (sum << 8) | (xor_val & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_matrix_power();
    for (;;);
}
