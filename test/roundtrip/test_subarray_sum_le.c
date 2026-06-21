/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Count Subarrays with Sum ≤ k fixture.
 *
 * For a sorted/arbitrary array, counts all contiguous subarrays
 * whose sum does not exceed a threshold k.
 * Brute-force O(n^2): break inner loop when sum > k (array is positive).
 *
 * Distinctive decompiler idioms:
 *   1. `for(i<n) s=0; for(j=i;j<n) s+=arr[j]; if(s<=k)cnt++; else break`
 *   2. Early break exploits non-negative array: once sum > k, extending further only grows it
 *   3. Two thresholds (k=5, k=8) compared for coverage
 *
 * Array: {1,2,3,4,5}, n=5
 *   k=5: subarrays ≤5 → {1},{2},{3},{4},{5},{1,2},{1,2,2}? → count=7
 *   k=8: additionally {1,2,3},{2,3},{4,4?} → count=9
 * Wait: {5} has sum=5 ≤5 ✓; {4,5}=9>8
 *
 * g_result = (2<<16)|(cnt1<<8)|cnt2 = 0x00020709
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_subarray_sum_le(void)
{
    static const int arr[5] = {1, 2, 3, 4, 5};
    int n = 5;
    int cnt1 = 0, cnt2 = 0, i, j;

    for (i = 0; i < n; i++) {
        int s = 0;
        for (j = i; j < n; j++) {
            s += arr[j];
            if (s <= 5) cnt1++;
            else break;
        }
    }
    for (i = 0; i < n; i++) {
        int s = 0;
        for (j = i; j < n; j++) {
            s += arr[j];
            if (s <= 8) cnt2++;
            else break;
        }
    }
    /* cnt1=7, cnt2=9 */
    g_result = (2u << 16)
             | ((uint32_t)cnt1 << 8)
             | (uint32_t)cnt2;
}

__attribute__((noreturn)) void _start(void)
{
    test_subarray_sum_le();
    for (;;);
}
