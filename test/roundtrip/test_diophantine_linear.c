/*
 * test_diophantine_linear.c
 * Linear Diophantine Equation solver: given a, b, c find integer (x,y) such
 * that a*x + b*y = c. Solution exists iff gcd(a,b) divides c.
 *
 * Algorithm:
 *   - Extended Euclidean: computes gcd(a,b) and coefficients (x0,y0) satisfying
 *     a*x0 + b*y0 = gcd(a,b).
 *   - Scale: if g|c, multiply by c/g to get a particular solution.
 *   - General solution: x = x0*(c/g) + (b/g)*t, y = y0*(c/g) - (a/g)*t.
 *   - Smallest non-negative x: t_min = ceil(-x0*(c/g) / (b/g)).
 *
 * Tests:
 *   1. 35x + 15y = 5: gcd=5, solution exists. Particular: x0=-1,y0=3 (scaled).
 *      Check: 35*(-1) + 15*3 = -35+45 = 10? Scale by 1: gcd=5,c/g=1 => x0=-1,y0=3.
 *      35*(-1)+15*3 = -35+45=10. Hmm, need c=10 or different. Let's use a=12,b=8,c=4.
 *      gcd(12,8)=4, c/g=1. ext_gcd(12,8): 12*1+8*(-1)=4 => x0=1,y0=-1. Verify: 12*1+8*(-1)=4. Yes.
 *   2. a=6,b=10,c=14: gcd=2, 2|14. Particular: ext_gcd(6,10)=>6*2+10*(-1)=2, scale by 7: x0=14,y0=-7.
 *      Verify: 6*14+10*(-7)=84-70=14. Yes.
 *   3. a=9,b=6,c=7: gcd=3, 3 does not divide 7 => NO solution. Return sentinel 0.
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Extended GCD: returns gcd, sets *px = x, *py = y such that a*x+b*y=gcd */
/* Uses 32-bit signed arithmetic only. */
static int32_t ext_gcd(int32_t a, int32_t b, int32_t *px, int32_t *py) {
    if (b == 0) {
        *px = 1; *py = 0;
        return a;
    }
    int32_t x1, y1;
    int32_t g = ext_gcd(b, a % b, &x1, &y1);
    *px = y1;
    *py = x1 - (a / b) * y1;
    return g;
}

/*
 * Solve ax + by = c.
 * Returns 1 if solution exists (sets *rx, *ry to particular solution), 0 otherwise.
 */
static uint32_t dioph_solve(int32_t a, int32_t b, int32_t c, int32_t *rx, int32_t *ry) {
    int32_t x0, y0;
    int32_t g = ext_gcd(a, b, &x0, &y0);
    if (g < 0) g = -g;
    if (c % g != 0) return 0u;  /* no solution */
    int32_t scale = c / g;
    *rx = x0 * scale;
    *ry = y0 * scale;
    return 1u;
}

static uint32_t run_diophantine_tests(void) {
    uint32_t n_tests = 0u;
    int32_t x, y;

    /*
     * Test 1: 12x + 8y = 4.
     * gcd(12,8)=4, 4|4 => SAT.
     * Particular solution: ext_gcd(12,8)=>12*1+8*(-1)=4, scale*1: x=1,y=-1.
     * Verify: 12*1 + 8*(-1) = 4. OK.
     * solvable1 = 1.
     */
    uint32_t solvable1 = dioph_solve(12, 8, 4, &x, &y);
    uint32_t verify1   = (solvable1 && (12*x + 8*y == 4)) ? 1u : 0u;
    n_tests++;

    /*
     * Test 2: 6x + 10y = 14.
     * gcd(6,10)=2, 2|14 => SAT. scale=7.
     * ext_gcd(6,10): 6*2+10*(-1)=2 => x0=2,y0=-1 scaled: x=14,y=-7.
     * Verify: 6*14+10*(-7)=84-70=14. OK.
     */
    uint32_t solvable2 = dioph_solve(6, 10, 14, &x, &y);
    uint32_t verify2   = (solvable2 && (6*x + 10*y == 14)) ? 1u : 0u;
    n_tests++;

    /*
     * Test 3: 9x + 6y = 7.
     * gcd(9,6)=3, 3 does not divide 7 => UNSAT.
     * solvable3 = 0.
     */
    uint32_t solvable3 = dioph_solve(9, 6, 7, &x, &y);
    n_tests++;

    /*
     * Pack result:
     *   n_tests=3=0x03
     *   metric_a = (verify1<<4)|(verify2<<3)|(solvable3<<2)|(solvable2<<1)|solvable1
     *            = (1<<4)|(1<<3)|(0<<2)|(1<<1)|1 = 16+8+0+2+1=27=0x1B
     *   metric_b = 0xC0|(verify1<<5)|(verify2<<4)|(solvable1<<3)|(solvable2<<2)|solvable3
     *            = 0xC0|32|16|8|4|0 = 0xC0+60=0xFC
     *   Bytes: 0x03, 0x1B, 0xFC — distinct, non-zero. Good.
     */
    uint32_t metric_a = (verify1 << 4u) | (verify2 << 3u) | (solvable3 << 2u)
                      | (solvable2 << 1u) | solvable1;
    uint32_t metric_b = 0xC0u | (verify1 << 5u) | (verify2 << 4u)
                      | (solvable1 << 3u) | (solvable2 << 2u) | solvable3;
    return (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    g_result = run_diophantine_tests();
    while (1) {}
}
