/* test_jacobi_symbol.c
 * Purpose   : Validate Jacobi symbol computation (number theory)
 * Algorithm : Jacobi(a, n) generalizes the Legendre symbol to composite n.
 *             Uses iterative quadratic reciprocity:
 *             1) Strip sign: if a<0, flip result if n≡3 (mod 4)
 *             2) Strip factors of 2: each 2 flips result if n≡3 or 5 (mod 8)
 *             3) Apply reciprocity: swap (a,n), flip if both ≡3 (mod 4)
 *             4) Reduce: a = a mod n
 *             Returns 0 if gcd(a,n)>1, else +1 or -1.
 * Input     : 9 pairs over small odd n: (1,3),(2,3),(1,5),(2,5),(3,5),
 *                                       (4,5),(1,7),(3,7),(5,7)
 * Expected  : Results: 1,-1,1,-1,-1,1,1,-1,-1
 *             count_pos=4, count_neg=5, n_pairs=9
 * g_result  = (n_pairs << 16) | (count_pos << 8) | count_neg
 *           = (9 << 16) | (4 << 8) | 5 = 0x090405
 */

#include <stdint.h>

volatile uint32_t g_result;

static int jacobi_sym(int a, int n) {
    int result = 1;
    if (a < 0) {
        a = -a;
        if ((n & 3) == 3) result = -result; /* n ≡ 3 (mod 4) */
    }
    while (a != 0) {
        /* Strip factors of 2 from a */
        while ((a & 1) == 0) {
            a >>= 1;
            int r = n & 7; /* n mod 8 */
            if (r == 3 || r == 5) result = -result;
        }
        /* Quadratic reciprocity: swap a and n */
        int tmp = a; a = n; n = tmp;
        if (((a & 3) == 3) && ((n & 3) == 3)) result = -result;
        a = a % n;
    }
    return (n == 1) ? result : 0;
}

void _start(void) {
    static const int as[] = { 1, 2, 1, 2, 3, 4, 1, 3, 5 };
    static const int ns[] = { 3, 3, 5, 5, 5, 5, 7, 7, 7 };
    const int n_pairs = 9;

    int count_pos = 0, count_neg = 0;
    for (int i = 0; i < n_pairs; i++) {
        int j = jacobi_sym(as[i], ns[i]);
        if (j > 0) count_pos++;
        else if (j < 0) count_neg++;
    }
    /* count_pos=4, count_neg=5, n_pairs=9 -> 0x090405 */
    g_result = ((uint32_t)n_pairs   << 16)
             | ((uint32_t)count_pos <<  8)
             | ((uint32_t)count_neg);
    while (1) {}
}
