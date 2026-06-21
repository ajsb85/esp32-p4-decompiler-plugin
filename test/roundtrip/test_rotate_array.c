/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Array Rotation (3-reversal in-place) fixture.
 *
 * Rotate an array right by k positions in-place using the 3-reversal method:
 *   1. reverse(arr, 0, n-k-1)   — reverse left part
 *   2. reverse(arr, n-k, n-1)   — reverse right part
 *   3. reverse(arr, 0, n-1)     — reverse whole array
 *
 * Distinctive decompiler idioms:
 *   1. `while (l < r) { swap(arr[l++], arr[r--]); }` — in-place reverse
 *   2. Three sequential calls to reverse with different sub-ranges
 *   3. `k = k % n` — normalise rotation amount
 *
 * Input: arr = {1,2,3,4,5,6,7}, n=7, k=2  →  {6,7,1,2,3,4,5}
 *
 * n    = 7
 * k    = 2
 * last = arr[n-1] = 5  (last element after rotation)
 *
 * g_result = (n << 16) | (k << 8) | last = 0x00070205
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── In-place reverse sub-range ─────────────────────────────────────────────── */

static void ra_reverse(int *arr, int l, int r)
{
    while (l < r) {
        int t    = arr[l];
        arr[l++] = arr[r];
        arr[r--] = t;
    }
}

/* ── Test entry point ────────────────────────────────────────────────────────── */

void test_rotate_array(void)
{
    int arr[] = {1, 2, 3, 4, 5, 6, 7};
    int n = 7, k = 2;

    k = k % n;                   /* normalise */
    ra_reverse(arr, 0, n - k - 1);  /* reverse left part  {5,4,3,2,1,6,7} */
    ra_reverse(arr, n - k, n - 1);  /* reverse right part {5,4,3,2,1,7,6} */
    ra_reverse(arr, 0, n - 1);      /* reverse whole      {6,7,1,2,3,4,5} */

    /* arr = {6,7,1,2,3,4,5}, last=5 */
    g_result = ((uint32_t)n << 16) | ((uint32_t)k << 8) | ((uint32_t)arr[n - 1] & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_rotate_array();
    for (;;);
}
