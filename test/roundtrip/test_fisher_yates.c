/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Fisher-Yates Shuffle (deterministic) fixture.
 *
 * Knuth / Fisher-Yates in-place shuffle: for i=0..n-2, pick j in [i,n) and
 * swap arr[i] with arr[j]. Uses a deterministic "random" function
 * `j = i + (i*3+7) % (n-i)` so the result is fully reproducible.
 *
 * Distinctive decompiler idioms:
 *   1. `for i=0..n-2: j = i + det_rand(i,n-i); swap(arr[i], arr[j])`
 *   2. `swap(arr[i], arr[j])` via temp — canonical swap idiom
 *   3. XOR of permutation == XOR of original (permutation invariant)
 *
 * Input: {1,2,3,4,5,6,7,8} n=8
 * After shuffle: {8,5,4,2,1,7,3,6}
 *   sum  = 36  (same as {1..8}: 36)
 *   xor  = 8   (XOR{1..8} = 8 regardless of order)
 *
 * g_result = (n << 16) | (sum << 8) | xor = 0x00082408
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FY_N 8

static int fy_arr[FY_N];

void test_fisher_yates(void)
{
    int init[FY_N] = {1, 2, 3, 4, 5, 6, 7, 8};
    for (int i = 0; i < FY_N; i++) fy_arr[i] = init[i];

    for (int i = 0; i < FY_N - 1; i++) {
        int j = i + (i * 3 + 7) % (FY_N - i);
        int tmp  = fy_arr[i];
        fy_arr[i] = fy_arr[j];
        fy_arr[j] = tmp;
    }

    uint32_t sum = 0, xr = 0;
    for (int i = 0; i < FY_N; i++) {
        sum += (uint32_t)fy_arr[i];
        xr  ^= (uint32_t)fy_arr[i];
    }

    g_result = ((uint32_t)FY_N << 16) | ((sum & 0xFFu) << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_fisher_yates();
    for (;;);
}
