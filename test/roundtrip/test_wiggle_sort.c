/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Wiggle Sort (one-pass) fixture.
 *
 * Rearranges array so that arr[0]<arr[1]>arr[2]<arr[3]>... in O(n):
 *   for i in 1..n-1:
 *     if (i%2==1 && arr[i] < arr[i-1]) or (i%2==0 && arr[i] > arr[i-1]):
 *       swap(arr[i], arr[i-1])
 *
 * Distinctive decompiler idioms:
 *   1. `if (i & 1) { if (arr[i] < arr[i-1]) swap; }`
 *   2. `else { if (arr[i] > arr[i-1]) swap; }`
 *   3. Count adjacent pairs satisfying wiggle property
 *
 * Input: {1,5,1,1,6,4}
 * After wiggle: {1,5,1,6,1,4}  (one valid wiggle arrangement)
 *   n_pairs_ok=5 (all 5 adjacent pairs satisfy wiggle), xor=1^5^1^6^1^4=6
 *
 * g_result = (6 << 16) | (5 << 8) | 6 = 0x00060506
 */
#include <stdint.h>

volatile uint32_t g_result;

#define WS_N 6

static int ws_arr[WS_N];

void test_wiggle_sort(void)
{
    static const int src[WS_N] = {1, 5, 1, 1, 6, 4};
    for (int i = 0; i < WS_N; i++) ws_arr[i] = src[i];

    for (int i = 1; i < WS_N; i++) {
        if ((i & 1) && ws_arr[i] < ws_arr[i-1]) {
            int t = ws_arr[i]; ws_arr[i] = ws_arr[i-1]; ws_arr[i-1] = t;
        } else if (!(i & 1) && ws_arr[i] > ws_arr[i-1]) {
            int t = ws_arr[i]; ws_arr[i] = ws_arr[i-1]; ws_arr[i-1] = t;
        }
    }

    int n_ok = 0;
    for (int i = 1; i < WS_N; i++) {
        if ((i & 1) ? ws_arr[i] > ws_arr[i-1] : ws_arr[i] < ws_arr[i-1])
            n_ok++;
    }

    uint32_t xr = 0;
    for (int i = 0; i < WS_N; i++) xr ^= (uint32_t)ws_arr[i];

    g_result = ((uint32_t)WS_N << 16)
             | ((uint32_t)(n_ok & 0xFF) << 8)
             | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_wiggle_sort();
    for (;;);
}
