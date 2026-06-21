/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Bucket Sort fixture.
 *
 * Sorts integers in [0, range) using a counting/bucket array.
 * Array {4,2,8,1,9,3,7,5,6,0} (n=10, range=10).
 * After sort: {0,1,2,3,4,5,6,7,8,9}.
 *
 * Distinctive decompiler idioms:
 *   1. `for(i=0; i<n; i++) bucket[arr[i]]++` — populate buckets
 *   2. `for(i=0; i<range; i++) while(bucket[i]--) arr[idx++]=i` — scatter back
 *   3. Result: largest=arr[n-1]=9, second=arr[n-2]=8
 *
 * g_result = (n<<16) | (largest<<8) | second = 0x000A0908
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_bucket_sort(void)
{
    int arr[10] = {4, 2, 8, 1, 9, 3, 7, 5, 6, 0};
    int n = 10, range = 10;
    static int bucket[10];
    int i, idx;

    for (i = 0; i < range; i++) bucket[i] = 0;
    for (i = 0; i < n; i++) bucket[arr[i]]++;

    idx = 0;
    for (i = 0; i < range; i++) {
        while (bucket[i]-- > 0) arr[idx++] = i;
    }
    /* arr[n-1]=9 (largest), arr[n-2]=8 (second largest) */
    g_result = ((uint32_t)n << 16)
             | ((uint32_t)arr[n-1] << 8)
             | (uint32_t)arr[n-2];
}

__attribute__((noreturn)) void _start(void)
{
    test_bucket_sort();
    for (;;);
}
