/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Matrix Exponentiation (Fibonacci via 2x2 matrix) fixture.
 *
 * Computes Fibonacci numbers using 2x2 matrix exponentiation:
 * [[1,1],[1,0]]^n = [[F(n+1),F(n)],[F(n),F(n-1)]]
 *
 * Distinctive decompiler idioms:
 *   1. `mat_mul(A, B, C)` — 2x2 matrix multiply with mod
 *   2. `while (exp > 0): if(exp&1) mat_mul(res,A,res); mat_mul(A,A,A); exp>>=1`
 *   3. `return res[0][1]` — extract F(n) from result matrix
 *
 * Test cases (n={10,12,14}):
 *   F(10)=55, F(12)=144, F(14)=377
 *   sum=576, sum%256=64, xor=55^144^377=478, xor%256=222
 *
 * g_result = (3 << 16) | (64 << 8) | 222 = 0x000340DE
 */
#include <stdint.h>

volatile uint32_t g_result;

#define ME_MOD 10000u

static void mat_mul(uint32_t a[2][2], uint32_t b[2][2], uint32_t c[2][2])
{
    uint32_t t[2][2];
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 2; j++) {
            t[i][j] = 0;
            for (int k = 0; k < 2; k++)
                t[i][j] = (t[i][j] + a[i][k] * b[k][j]) % ME_MOD;
        }
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 2; j++)
            c[i][j] = t[i][j];
}

static uint32_t fib_mat(uint32_t n)
{
    uint32_t res[2][2] = {{1,0},{0,1}};
    uint32_t A[2][2]   = {{1,1},{1,0}};
    while (n > 0) {
        if (n & 1u) mat_mul(res, A, res);
        mat_mul(A, A, A);
        n >>= 1;
    }
    return res[0][1];
}

void test_matrix_exp(void)
{
    uint32_t f10 = fib_mat(10); /* 55  */
    uint32_t f12 = fib_mat(12); /* 144 */
    uint32_t f14 = fib_mat(14); /* 377 */

    uint32_t sum = (f10 + f12 + f14) & 0xFFu; /* 576 % 256 = 64 */
    uint32_t xr  = (f10 ^ f12 ^ f14) & 0xFFu; /* 478 % 256 = 222 */

    g_result = (3u << 16) | (sum << 8) | xr;
}

__attribute__((noreturn)) void _start(void)
{
    test_matrix_exp();
    for (;;);
}
