/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Consecutive Sequence (O(n^2)).
 *
 * For each element that has no predecessor (arr[i]-1 not present),
 * extend forward to measure the consecutive run length. Track maximum.
 *
 * Distinctive decompiler idioms:
 *   1. `for(j<n) if(arr[j]==arr[i]-1){is_start=0;break}` — predecessor check
 *   2. `cur=arr[i]+1; while(any arr[j]==cur){len++;cur++}` — extend run
 *   3. `if(len>best)best=len` — track maximum
 *
 * Array 1: {100,4,200,1,3,2} → longest=4 (1,2,3,4)
 * Array 2: {0,3,7,2,5,8,4,6,0,1} → longest=9 (0,1,2,3,4,5,6,7,8)
 *
 * g_result = (2<<16)|(best1<<8)|best2 = 0x00020409
 */
#include <stdint.h>

volatile uint32_t g_result;

static int lcs_find(const int *arr, int n)
{
    int best = 0;
    for (int i = 0; i < n; i++) {
        int is_start = 1;
        for (int j = 0; j < n; j++)
            if (arr[j] == arr[i] - 1) { is_start = 0; break; }
        if (!is_start) continue;

        int len = 1, cur = arr[i] + 1, go = 1;
        while (go) {
            go = 0;
            for (int j = 0; j < n; j++)
                if (arr[j] == cur) { len++; cur++; go = 1; break; }
        }
        if (len > best) best = len;
    }
    return best;
}

void test_consecutive_seq(void)
{
    static const int a1[6]  = {100, 4, 200, 1, 3, 2};
    static const int a2[10] = {0, 3, 7, 2, 5, 8, 4, 6, 0, 1};

    int best1 = lcs_find(a1, 6);
    int best2 = lcs_find(a2, 10);
    /* best1=4, best2=9 */
    g_result = (2u << 16)
             | ((uint32_t)best1 << 8)
             | (uint32_t)best2;
}

__attribute__((noreturn)) void _start(void)
{
    test_consecutive_seq();
    for (;;);
}
