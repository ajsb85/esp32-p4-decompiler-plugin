/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Next Permutation (in-place) fixture.
 *
 * Finds the next lexicographic permutation in-place:
 *   1. Find rightmost i where arr[i] < arr[i+1]
 *   2. Find rightmost j where arr[j] > arr[i]
 *   3. Swap arr[i] and arr[j]
 *   4. Reverse arr[i+1..]
 *
 * Distinctive decompiler idioms:
 *   1. `i = n-2; while(i>=0 && arr[i]>=arr[i+1]) i--`
 *   2. `j = n-1; while(arr[j]<=arr[i]) j--; swap(arr[i],arr[j])`
 *   3. `reverse(arr+i+1, arr+n-1)` — reversal of suffix
 *
 * Start: {1,2,3} → apply 3 times → final: {2,3,1}
 *   n_steps=3, final_sum=2+3+1=6, final_first^last=2^1=3
 *
 * g_result = (3 << 16) | (6 << 8) | 3 = 0x00030603
 */
#include <stdint.h>

volatile uint32_t g_result;

#define NP_N 3

static int np_arr[NP_N];

static void np_next(void)
{
    int i = NP_N - 2;
    while (i >= 0 && np_arr[i] >= np_arr[i+1]) i--;
    if (i >= 0) {
        int j = NP_N - 1;
        while (np_arr[j] <= np_arr[i]) j--;
        int t = np_arr[i]; np_arr[i] = np_arr[j]; np_arr[j] = t;
    }
    int lo = i + 1, hi = NP_N - 1;
    while (lo < hi) {
        int t = np_arr[lo]; np_arr[lo] = np_arr[hi]; np_arr[hi] = t;
        lo++; hi--;
    }
}

void test_next_perm(void)
{
    np_arr[0] = 1; np_arr[1] = 2; np_arr[2] = 3;
    np_next(); /* {1,3,2} */
    np_next(); /* {2,1,3} */
    np_next(); /* {2,3,1} */

    uint32_t sum  = (uint32_t)(np_arr[0] + np_arr[1] + np_arr[2]); /* 6 */
    uint32_t fxl  = (uint32_t)(np_arr[0] ^ np_arr[NP_N-1]);        /* 3 */

    g_result = (3u << 16) | ((sum & 0xFFu) << 8) | (fxl & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_next_perm();
    for (;;);
}
