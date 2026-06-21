/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Pancake Sort fixture.
 *
 * Sorts an array using only prefix reversals ("flips").  Each step:
 *   1. Find the maximum element in arr[0..size-1]
 *   2. If it is not at the front (mi != 0), flip arr[0..mi] to bring it there
 *   3. Flip arr[0..size-1] to move it to its final position
 *
 * Distinctive decompiler idioms:
 *   1. find-max scan inside the outer shrink loop: `for (i=1; i<size; i++) if (arr[i]>arr[mi]) mi=i`
 *   2. Double flip pattern: ps_flip(arr, mi) then ps_flip(arr, size-1)
 *   3. ps_flip uses lo/hi swap converging inward: `while (lo<hi) swap(arr[lo++], arr[hi--])`
 *   4. Skip-if-in-place guard: `if (mi == size-1) continue`
 *
 * Input (n=6): {3, 6, 1, 5, 2, 4}
 * Sorted:      {1, 2, 3, 4, 5, 6}
 *
 * n       = 6
 * last    = arr[n-1] = 6
 * xor_all = 1^2^3^4^5^6 = 7
 *
 * g_result = (n << 16) | (last << 8) | xor_all = 0x00060607
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Pancake Sort ────────────────────────────────────────────────────────── */

#define PS_N 6

static int ps_arr[PS_N];

static void ps_flip(int *arr, int k)
{
    int lo = 0, hi = k;
    while (lo < hi) {
        int tmp = arr[lo]; arr[lo++] = arr[hi]; arr[hi--] = tmp;
    }
}

static void pancake_sort(int *arr, int n)
{
    for (int size = n; size > 1; size--) {
        int mi = 0;
        for (int i = 1; i < size; i++)
            if (arr[i] > arr[mi]) mi = i;
        if (mi == size - 1) continue;
        if (mi != 0) ps_flip(arr, mi);
        ps_flip(arr, size - 1);
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_pancake_sort(void)
{
    static const int src[PS_N] = {3, 6, 1, 5, 2, 4};
    for (int i = 0; i < PS_N; i++) ps_arr[i] = src[i];

    pancake_sort(ps_arr, PS_N);
    /* sorted: {1,2,3,4,5,6} */

    uint32_t xor_all = 0;
    for (int i = 0; i < PS_N; i++) xor_all ^= (uint32_t)ps_arr[i];

    g_result = ((uint32_t)PS_N << 16)
             | ((uint32_t)ps_arr[PS_N - 1] << 8)
             | (xor_all & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_pancake_sort();
    for (;;);
}
