/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Count Inversions via Merge Sort fixture.
 *
 * An inversion is a pair (i,j): i<j but arr[i]>arr[j].
 * Merge sort counts inversions in O(n log n):
 *   during merge: whenever arr[right] < arr[left],
 *   all remaining left-half elements form inversions → cnt += (mid - i).
 *
 * Distinctive decompiler idioms:
 *   1. cnt += mid - i   ← inversion count in merge step
 *   2. Recursive divide at mid = (lo+hi)/2
 *   3. Output array tmp[] written back into arr[]
 *
 * Input (n=6, fully reversed): {6, 5, 4, 3, 2, 1}
 *
 * Expected inversions = n*(n-1)/2 = 6*5/2 = 15
 * XOR of array elements: 6^5^4^3^2^1 = 7
 *
 * n         = 6
 * inv_count = 15  (0x0F)
 * xor_arr   = 7
 *
 * g_result = (n << 16) | (inv_count << 8) | xor_arr = 0x00060F07
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Merge sort inversion count ───────────────────────────────────────────── */

#define CI_N 6

static int ci_tmp[CI_N];

static int merge_count(int *arr, int lo, int hi)
{
    if (hi - lo <= 1) return 0;
    int mid = (lo + hi) / 2;
    int cnt = merge_count(arr, lo, mid) + merge_count(arr, mid, hi);

    int i = lo, j = mid, k = lo;
    while (i < mid && j < hi) {
        if (arr[i] <= arr[j]) {
            ci_tmp[k++] = arr[i++];
        } else {
            cnt += mid - i;           /* key: all remaining left elems invert with arr[j] */
            ci_tmp[k++] = arr[j++];
        }
    }
    while (i < mid) ci_tmp[k++] = arr[i++];
    while (j < hi)  ci_tmp[k++] = arr[j++];
    for (int x = lo; x < hi; x++) arr[x] = ci_tmp[x];
    return cnt;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_count_inversions(void)
{
    static const int src[CI_N] = {6, 5, 4, 3, 2, 1};
    int arr[CI_N];
    for (int i = 0; i < CI_N; i++) arr[i] = src[i];

    uint32_t xor_arr = 0;
    for (int i = 0; i < CI_N; i++) xor_arr ^= (uint32_t)src[i];

    int inv_count = merge_count(arr, 0, CI_N);
    /* inv_count=15, xor_arr=7 */

    g_result = ((uint32_t)CI_N << 16)
             | ((uint32_t)inv_count << 8)
             | (xor_arr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_count_inversions();
    for (;;);
}
