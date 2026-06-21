/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Two-Sum Pairs (two-pointer on sorted array).
 *
 * Counts all pairs in a sorted array that sum to a given target.
 * Uses two-pointer scan: lo from left, hi from right.
 *
 * Distinctive decompiler idioms:
 *   1. `lo=0; hi=n-1; while(lo<hi)` — two-pointer setup
 *   2. `s=arr[lo]+arr[hi]; if(s==t){cnt++;lo++;hi--;}` — pair found, advance both
 *   3. `else if(s<t)lo++; else hi--` — steer toward target
 *
 * Array: sorted {1..10}, n=10
 *   target=10: pairs (1,9),(2,8),(3,7),(4,6) → 4
 *   target=15: pairs (5,10),(6,9),(7,8) → 3
 *   target=7:  pairs (1,6),(2,5),(3,4) → 3
 *
 * sum_counts=10, xor_counts=4^3^3=4
 *
 * g_result = (3<<16)|(sum_counts<<8)|xor_counts = 0x00030A04
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_two_sum_pairs(void)
{
    static const int arr[10] = {1,2,3,4,5,6,7,8,9,10};
    int n = 10;
    int targets[3] = {10, 15, 7};
    int cnt[3];

    for (int t = 0; t < 3; t++) {
        cnt[t] = 0;
        int lo = 0, hi = n - 1;
        while (lo < hi) {
            int s = arr[lo] + arr[hi];
            if (s == targets[t]) { cnt[t]++; lo++; hi--; }
            else if (s < targets[t]) lo++;
            else hi--;
        }
    }
    /* cnt={4,3,3}, sum=10, xor=4^3^3=4 */
    int sum = cnt[0] + cnt[1] + cnt[2];
    int xr  = cnt[0] ^ cnt[1] ^ cnt[2];
    g_result = (3u << 16)
             | ((uint32_t)sum << 8)
             | (uint32_t)xr;
}

__attribute__((noreturn)) void _start(void)
{
    test_two_sum_pairs();
    for (;;);
}
