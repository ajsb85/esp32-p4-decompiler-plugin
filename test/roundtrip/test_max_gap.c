/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Maximum Gap fixture.
 *
 * Finds the maximum difference between successive elements in a sorted array.
 * Naive approach: sort + linear scan.
 *
 * Distinctive decompiler idioms:
 *   1. `for i in 1..n: if arr[i]-arr[i-1] > max_gap: max_gap = arr[i]-arr[i-1]`
 *   2. `sort first` — comparison-based sort before gap computation
 *   3. `n < 2: return 0` — edge case
 *
 * Test cases (pre-sorted arrays):
 *   {1,3,6,10,18}: gaps {2,3,4,8}    → max=8
 *   {1,9}:         gaps {8}           → max=8
 *   {1,4,7,9,11,15,20}: gaps {3,3,2,2,4,5} → max=5
 *   n_tests=3, sum_maxgap=8+8+5=21=0x15, xor=8^8^5=5=0x05
 *
 * g_result = (3 << 16) | (21 << 8) | 5 = 0x00031505
 */
#include <stdint.h>

volatile uint32_t g_result;

static int mg_max_gap(const int *arr, int n)
{
    if (n < 2) return 0;
    int mg = 0;
    for (int i = 1; i < n; i++) {
        int gap = arr[i] - arr[i-1];
        if (gap > mg) mg = gap;
    }
    return mg;
}

void test_max_gap(void)
{
    static const int a0[5] = {1, 3, 6, 10, 18};
    static const int a1[2] = {1, 9};
    static const int a2[7] = {1, 4, 7, 9, 11, 15, 20};

    int r0 = mg_max_gap(a0, 5); /* 8 */
    int r1 = mg_max_gap(a1, 2); /* 8 */
    int r2 = mg_max_gap(a2, 7); /* 5 */

    g_result = (3u << 16)
             | ((uint32_t)((r0 + r1 + r2) & 0xFF) << 8)
             | ((uint32_t)((r0 ^ r1 ^ r2) & 0xFF));
}

__attribute__((noreturn)) void _start(void)
{
    test_max_gap();
    for (;;);
}
