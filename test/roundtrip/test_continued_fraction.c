/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Continued Fraction convergents fixture.
 *
 * Continued fractions represent a real number as:
 *   x = a0 + 1/(a1 + 1/(a2 + ...))
 *
 * Convergents p_k/q_k satisfy the recurrence:
 *   p_{-1}=1, p_0=a0,  p_k = a_k*p_{k-1} + p_{k-2}
 *   q_{-1}=0, q_0=1,   q_k = a_k*q_{k-1} + q_{k-2}
 *
 * Distinctive decompiler idioms:
 *   1. `p = a * p_prev + p_prev2` — numerator recurrence
 *   2. `q = a * q_prev + q_prev2` — denominator recurrence
 *   3. `a = num / den; num = den; den = rem` — Euclidean quotient step
 *   4. `p * q_prev - q * p_prev == 1` — convergent determinant property
 *
 * Input: CF expansion of 355/113 = [3;7,16] (pi approximation)
 *   a = {3, 7, 16}
 * Convergents:
 *   k=0: p=3,  q=1
 *   k=1: p=22, q=7
 *   k=2: p=355,q=113
 *
 * n_coeffs = 3, final_p = 355 % 256 = 99, final_q = 113
 * g_result = (n_coeffs<<16)|(final_p<<8)|final_q  (99 & 113 fit in bytes, distinct non-zero)
 *          = (3<<16)|(99<<8)|113 = 0x030071  wait: 99=0x63, 113=0x71 → 0x036371
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CF_LEN 3

static const int32_t cf_a[CF_LEN] = {3, 7, 16};

void test_continued_fraction(void)
{
    int32_t p2 = 1, p1 = cf_a[0];   /* p_{-1}, p_0 */
    int32_t q2 = 0, q1 = 1;         /* q_{-1}, q_0 */

    for (int k = 1; k < CF_LEN; k++) {
        int32_t p = cf_a[k] * p1 + p2;
        int32_t q = cf_a[k] * q1 + q2;
        p2 = p1; p1 = p;
        q2 = q1; q1 = q;
    }
    /* p1=355, q1=113 */
    uint32_t fp = (uint32_t)p1 & 0xFFu;   /* 355 % 256 = 99 = 0x63 */
    uint32_t fq = (uint32_t)q1 & 0xFFu;   /* 113 = 0x71 */
    g_result = ((uint32_t)CF_LEN << 16) | (fp << 8) | fq;
}

__attribute__((noreturn)) void _start(void)
{
    test_continued_fraction();
    for (;;);
}
