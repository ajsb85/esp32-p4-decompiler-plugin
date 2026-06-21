/* SPDX-License-Identifier: Apache-2.0
 * Extended round-trip test: 3x3 matrix multiply + determinant.
 *
 * Exercises: nested loops (triple for), 2D array indexing, multiply-
 *            accumulate, integer determinant via cofactor expansion.
 *
 * Expected pattern detection: matrix_ops (triple nested for + MAC)
 *
 * Test matrices:
 *   A = [[1,2,3],[4,5,6],[7,8,9]]   (singular: det=0)
 *   B = [[9,8,7],[6,5,4],[3,2,1]]
 *   C = A × B
 *
 *   A×B row 0: [1*9+2*6+3*3, 1*8+2*5+3*2, 1*7+2*4+3*1]
 *            = [9+12+9, 8+10+6, 7+8+3] = [30, 24, 18]
 *   Row 1:    [4*9+5*6+6*3, 4*8+5*5+6*2, 4*7+5*4+6*1]
 *            = [36+30+18, 32+25+12, 28+20+6] = [84, 69, 54]
 *   Row 2:    [7*9+8*6+9*3, 7*8+8*5+9*2, 7*7+8*4+9*1]
 *            = [63+48+27, 56+40+18, 49+32+9] = [138, 114, 90]
 *
 *   Sum of all C elements:
 *     30+24+18 + 84+69+54 + 138+114+90 = 621
 *   XOR of all C elements:
 *     30^24^18 ^ 84^69^54 ^ 138^114^90
 *
 * Determinant of A: 1(5*9-6*8)-2(4*9-6*7)+3(4*8-5*7)
 *                 = 1(45-48)-2(36-42)+3(32-35)
 *                 = 1(-3)-2(-6)+3(-3) = -3+12-9 = 0
 *
 * g_result = (uint32_t)(C_xor ^ (det_A == 0 ? 0xABu : 0))
 */
#include <stdint.h>

volatile uint32_t g_result;

#define N 3

static void mat_mul(const int a[N][N], const int b[N][N], int c[N][N]) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            int acc = 0;
            for (int k = 0; k < N; k++)
                acc += a[i][k] * b[k][j];
            c[i][j] = acc;
        }
    }
}

static int mat_det3(const int m[N][N]) {
    return m[0][0] * (m[1][1]*m[2][2] - m[1][2]*m[2][1])
         - m[0][1] * (m[1][0]*m[2][2] - m[1][2]*m[2][0])
         + m[0][2] * (m[1][0]*m[2][1] - m[1][1]*m[2][0]);
}

static uint32_t mat_xor(const int m[N][N]) {
    uint32_t acc = 0;
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            acc ^= (uint32_t)m[i][j];
    return acc;
}

void _start(void) {
    const int A[N][N] = {{1,2,3},{4,5,6},{7,8,9}};
    const int B[N][N] = {{9,8,7},{6,5,4},{3,2,1}};
    int C[N][N];

    mat_mul(A, B, C);

    int det_a = mat_det3(A);   /* = 0  (A is singular) */
    uint32_t c_xor = mat_xor(C);

    /*
     * C element XOR:
     *   30^24^18 ^ 84^69^54 ^ 138^114^90
     *   = (30^24)=6, 6^18=20
     *   = (84^69)=25, 25^54=47
     *   = (138^114)=24+16=? let me just let the hardware compute it
     * XOR is deterministic — the native verification script checks it.
     */

    g_result = c_xor ^ (uint32_t)(det_a == 0 ? 0xABu : 0x00u);

    for (;;);
}
