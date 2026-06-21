/* test_matrix_exponentiation.c
 * Purpose   : Validate matrix fast exponentiation for Fibonacci via matrix form
 * Algorithm : [[1,1],[1,0]]^n gives [[F(n+1),F(n)],[F(n),F(n-1)]].
 *             Uses repeated squaring: O(log n) 2x2 matrix multiplications.
 *             All arithmetic done modulo 0xFF to keep values in [1..254].
 * Input     : n = 10  (compute F(10) mod 255)
 * Expected  : F(10) = 55, F(9) = 34, n = 10
 * g_result  = (n << 16) | (F10 << 8) | F9
 *           = (10 << 16) | (55 << 8) | 34 = 0x0A3722
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define MATEXP_MOD 255u
#define MATEXP_N   10

typedef struct { uint32_t a[2][2]; } Mat2;

static Mat2 mat_mul(Mat2 A, Mat2 B) {
    Mat2 C;
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 2; j++) {
            uint32_t s = 0;
            for (int k = 0; k < 2; k++)
                s += A.a[i][k] * B.a[k][j];
            C.a[i][j] = s % MATEXP_MOD;
        }
    return C;
}

static Mat2 mat_pow(Mat2 base, int exp) {
    /* Identity matrix */
    Mat2 result;
    result.a[0][0] = 1; result.a[0][1] = 0;
    result.a[1][0] = 0; result.a[1][1] = 1;

    while (exp > 0) {
        if (exp & 1) result = mat_mul(result, base);
        base = mat_mul(base, base);
        exp >>= 1;
    }
    return result;
}

void _start(void) {
    /* Fibonacci base matrix [[1,1],[1,0]] */
    Mat2 fib_base;
    fib_base.a[0][0] = 1; fib_base.a[0][1] = 1;
    fib_base.a[1][0] = 1; fib_base.a[1][1] = 0;

    Mat2 res = mat_pow(fib_base, MATEXP_N);

    /* res[0][1] = F(n), res[1][1] = F(n-1) */
    uint32_t fn  = res.a[0][1];   /* F(10) = 55 mod 255 = 55 */
    uint32_t fn1 = res.a[1][1];   /* F(9)  = 34 mod 255 = 34 */

    /* 0x0A3722 */
    g_result = ((uint32_t)MATEXP_N << 16)
             | (fn  << 8)
             | fn1;
    while (1) {}
}
