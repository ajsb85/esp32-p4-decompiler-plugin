/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Maximum Product Subarray fixture.
 *
 * Track both max and min product ending at each position.
 * Both are needed because a negative × negative becomes positive.
 *
 * Distinctive decompiler idioms:
 *   1. `maxp=minp=ans=arr[0]` — initialize to first element
 *   2. `tmp=maxp; maxp=max(a,tmp*a,minp*a); minp=min(...)` — three-way max/min
 *   3. `if(maxp>ans)ans=maxp` — rolling best result
 *
 * Arrays:
 *   {2,3,-2,4}  → max product = 6 (subarray {2,3})
 *   {-2,0,-1}   → max product = 0
 *   {-2,3,-4}   → max product = 24 (full array)
 *
 * n_tests=3, res[0]=6=0x06, xor=6^0^24=30=0x1E
 *
 * g_result = (3<<16)|(res[0]<<8)|(xor_res) = 0x0003061E
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_max_product_sub(void)
{
    static const int arrs[3][4] = {
        {2,3,-2,4}, {-2,0,-1,0}, {-2,3,-4,0}
    };
    static const int ns[3] = {4, 3, 3};
    int res[3];

    for (int t = 0; t < 3; t++) {
        int n = ns[t];
        int maxp = arrs[t][0], minp = arrs[t][0], ans = arrs[t][0];
        for (int i = 1; i < n; i++) {
            int a = arrs[t][i], tmp = maxp;
            /* new_max = max(a, tmp*a, minp*a) */
            maxp = a;
            if (tmp * a > maxp) maxp = tmp * a;
            if (minp * a > maxp) maxp = minp * a;
            /* new_min = min(a, tmp*a, minp*a) */
            minp = a;
            if (tmp * a < minp) minp = tmp * a;
            if (arrs[t][i-1] != 0 && minp > arrs[t][i-1] * arrs[t][i])
                minp = arrs[t][i-1] * arrs[t][i];
            if (maxp > ans) ans = maxp;
        }
        res[t] = ans;
    }

    int xr = res[0] ^ res[1] ^ res[2];
    /* res={6,0,24}, xor=6^0^24=30=0x1E */
    g_result = (3u << 16)
             | ((uint32_t)res[0] << 8)
             | (uint32_t)xr;
}

__attribute__((noreturn)) void _start(void)
{
    test_max_product_sub();
    for (;;);
}
