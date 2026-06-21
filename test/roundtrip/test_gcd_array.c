/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — GCD and LCM of an Array fixture.
 *
 * Compute the GCD and LCM of all elements in an array using the iterative
 * Euclidean algorithm for GCD and the identity lcm(a,b)=a/gcd(a,b)*b.
 *
 * Distinctive decompiler idioms:
 *   1. `while(b){int t=b; b=a%b; a=t;} return a` — Euclidean GCD
 *   2. `lcm(a,b) = a/gcd(a,b)*b` — compute LCM without overflow
 *   3. `for(i=1..n-1): tg=gcd(tg,arr[i]); tl=lcm(tl,arr[i])` — fold over array
 *   4. final `tg` and `tl` are GCD/LCM of the whole array
 *
 * Array {12,18,24,36} (n=4):
 *   GCD(12,18,24,36) = 6
 *   LCM(12,18,24,36) = 72
 *
 * n=4, gcd=6, lcm%256=72=0x48
 *
 * g_result = (4<<16) | (6<<8) | 72 = 0x00040648
 */
#include <stdint.h>

volatile uint32_t g_result;

static int ga_gcd(int a, int b)
{
    while (b) { int t = b; b = a % b; a = t; }
    return a;
}

static int ga_lcm(int a, int b)
{
    return a / ga_gcd(a, b) * b;
}

void test_gcd_array(void)
{
    static const int arr[] = {12, 18, 24, 36};
    int n = 4;
    int tg = arr[0], tl = arr[0];
    for (int i = 1; i < n; i++) {
        tg = ga_gcd(tg, arr[i]);
        tl = ga_lcm(tl, arr[i]);
    }
    /* tg=6, tl=72 */
    g_result = ((uint32_t)n << 16) | ((uint32_t)(tg & 0xFF) << 8) | (uint32_t)(tl & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_gcd_array();
    for (;;);
}
