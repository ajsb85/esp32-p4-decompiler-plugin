/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — House Robber II (Circular DP).
 *
 * Houses arranged in a circle: can't rob both first and last.
 * Solution: max(rob[0..n-2], rob[1..n-1]) where rob[] is linear DP.
 *
 * Distinctive decompiler idioms:
 *   1. `p2=0; p1=0; for(i=lo;i<=hi) cur=arr[i]+p2; p2=max(p1,p2); p1=cur`
 *   2. `r=rob_lin(arr,0,n-2); b=rob_lin(arr,1,n-1); result=max(r,b)` — two passes
 *   3. Final result encodes 4 test sums and XOR
 *
 * 4 circular house arrays:
 *   {2,3,2}:    r=3 (rob 3)
 *   {1,2,3,1}:  r=4 (rob 1+3)
 *   {2,1,1,2}:  r=3 (rob 2+1 or 1+2)
 *   {5,1,1,5}:  r=6 (rob 5+1)
 *
 * n_tests=4, sum=16, xor=3^4^3^6=2
 *
 * g_result = (4<<16)|(sum<<8)|(xor) = 0x00041002
 */
#include <stdint.h>

volatile uint32_t g_result;

static int rob_lin(const int *a, int lo, int hi)
{
    int p2 = 0, p1 = 0;
    for (int i = lo; i <= hi; i++) {
        int cur = a[i] + p2;
        p2 = (p1 > p2) ? p1 : p2;
        p1 = cur;
    }
    return (p1 > p2) ? p1 : p2;
}

void test_house_robber2(void)
{
    static const int arrs[4][4] = {
        {2,3,2,0}, {1,2,3,1}, {2,1,1,2}, {5,1,1,5}
    };
    static const int ns[4] = {3, 4, 4, 4};
    int r[4], i;

    for (i = 0; i < 4; i++) {
        int a = rob_lin(arrs[i], 0, ns[i]-2);
        int b = rob_lin(arrs[i], 1, ns[i]-1);
        r[i] = (a > b) ? a : b;
    }

    int sum = r[0] + r[1] + r[2] + r[3];
    int xr  = r[0] ^ r[1] ^ r[2] ^ r[3];
    /* sum=16=0x10, xr=3^4^3^6=2 */
    g_result = (4u << 16)
             | ((uint32_t)sum << 8)
             | (uint32_t)xr;
}

__attribute__((noreturn)) void _start(void)
{
    test_house_robber2();
    for (;;);
}
