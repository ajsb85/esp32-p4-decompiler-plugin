/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Pell Equation solver fixture.
 *
 * Pell's equation: x^2 - D*y^2 = 1
 * The fundamental solution (x1, y1) is found via the periodic continued
 * fraction expansion of sqrt(D):
 *   a0 = floor(sqrt(D))
 *   At each step: m_{i+1} = d_i*a_i - m_i, d_{i+1} = (D-m_{i+1}^2)/d_i,
 *                 a_{i+1} = floor((a0+m_{i+1})/d_{i+1})
 *   Compute convergents p_k/q_k; when period ends (a_k == 2*a0),
 *   if period length is even: (p_{r-1}, q_{r-1}); if odd: (p_{2r-1}, q_{2r-1}).
 *
 * Distinctive decompiler idioms:
 *   1. `a0 = isqrt(D)` — integer square root
 *   2. `m = d*a - m; d = (D - m*m)/d; a = (a0+m)/d` — CF step
 *   3. `p = a*p_prev + p_prev2; q = a*q_prev + q_prev2` — convergent update
 *   4. `if (a == 2*a0) break` — period end detection
 *   5. `p*p - D*q*q == 1` — solution verification
 *
 * Test case: D=5, equation x^2 - 5*y^2 = 1
 *   CF of sqrt(5): a0=2, period=[4], len=1 (odd)
 *   Need 2 periods: convergents at k=0,1 (a={2,4,4,...})
 *   k=0: p=2,q=1  (2^2-5*1^2=-1, not solution for odd period)
 *   k=1: p=9,q=4  (9^2-5*16=81-80=1, solution!)
 *   So x1=9, y1=4
 *
 * n_iters used = 2 (even: solution found at 2nd convergent)
 * x1_low = 9, y1 = 4
 * g_result = (n_iters<<16)|(x1_low<<8)|y1 = (2<<16)|(9<<8)|4 = 0x020904
 */
#include <stdint.h>

volatile uint32_t g_result;

static int32_t pe_isqrt(int32_t n)
{
    if (n < 0) return 0;
    int32_t x = 1;
    while (x * x <= n) x++;
    return x - 1;
}

void test_pell_equation(void)
{
    const int32_t D = 5;
    int32_t a0 = pe_isqrt(D);

    int32_t m  = 0, d = 1, a = a0;
    int32_t p2 = 1, p1 = a0;
    int32_t q2 = 0, q1 = 1;
    int32_t n_iters = 1;

    /* Iterate CF convergents until Pell solution found */
    for (int iter = 0; iter < 20; iter++) {
        m = d * a - m;
        d = (D - m * m) / d;
        a = (a0 + m) / d;

        int32_t p = a * p1 + p2;
        int32_t q = a * q1 + q2;
        n_iters++;

        if (p * p - D * q * q == 1) {
            /* Found fundamental solution */
            uint32_t xl = (uint32_t)p & 0xFFu;
            uint32_t yl = (uint32_t)q & 0xFFu;
            g_result = ((uint32_t)n_iters << 16) | (xl << 8) | yl;
            return;
        }
        p2 = p1; p1 = p;
        q2 = q1; q1 = q;
    }
    /* Should not reach here for D=5 */
    g_result = 0xDEADBEEFu;
}

__attribute__((noreturn)) void _start(void)
{
    test_pell_equation();
    for (;;);
}
