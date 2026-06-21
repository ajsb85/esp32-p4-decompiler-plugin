/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Extended Euclidean Algorithm fixture.
 *
 * Computes gcd(a,b) and Bezout coefficients x,y such that a*x + b*y = gcd(a,b).
 * Recursive: gcd_ext(a,b,&x,&y): if b==0: x=1,y=0,return a;
 *             r=gcd_ext(b,a%b,&x1,&y1); x=y1; y=x1-(a/b)*y1;
 *
 * Distinctive decompiler idioms:
 *   1. `if (b == 0) { *x = 1; *y = 0; return a; }` — base case
 *   2. `*x = y1; *y = x1 - (a / b) * y1;` — coefficient update
 *   3. `assert(a*x + b*y == g)` — Bezout identity verification
 *
 * Test cases:
 *   gcd(12, 8):  g=4,  x=1,  y=-1  (12*1+8*(-1)=4)
 *   gcd(21, 14): g=7,  x=1,  y=-1  (21*1+14*(-1)=7)
 *   gcd(45, 30): g=15, x=1,  y=-1  (45*1+30*(-1)=15)
 *
 * sum_gcd=4+7+15=26=0x1A, xor_gcd=4^7^15=12=0x0C
 * g_result = (3 << 16) | (26 << 8) | 12 = 0x00031A0C
 */
#include <stdint.h>

volatile uint32_t g_result;

static int ge_ext(int a, int b, int *x, int *y)
{
    if (b == 0) { *x = 1; *y = 0; return a; }
    int x1, y1;
    int g = ge_ext(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

void test_gcd_ext(void)
{
    int x, y;
    int g0 = ge_ext(12, 8,  &x, &y);  /* 4  */
    int g1 = ge_ext(21, 14, &x, &y);  /* 7  */
    int g2 = ge_ext(45, 30, &x, &y);  /* 15 */

    uint32_t sum = (uint32_t)(g0 + g1 + g2); /* 26 */
    uint32_t xr  = (uint32_t)(g0 ^ g1 ^ g2); /* 12 */

    g_result = (3u << 16) | ((sum & 0xFFu) << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_gcd_ext();
    for (;;);
}
