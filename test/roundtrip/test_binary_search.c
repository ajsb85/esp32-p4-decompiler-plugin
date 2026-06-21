/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Binary search (range count) round-trip fixture.
 *
 * Binary search on a sorted integer array: find the leftmost and rightmost
 * occurrences of a target value, then compute the count of occurrences.
 *
 * Two separate binary search calls (each with a lo/hi/mid loop):
 *
 *   bs_first(arr, n, target): returns index of first occurrence of target,
 *     or -1.  When arr[mid]==target, record mid as candidate and set hi=mid-1
 *     to continue searching left.
 *
 *   bs_last(arr, n, target): returns index of last occurrence of target,
 *     or -1.  When arr[mid]==target, record mid as candidate and set lo=mid+1
 *     to continue searching right.
 *
 * Input array (10 elements, sorted):
 *   {2, 4, 4, 4, 4, 8, 12, 16, 20, 24}
 *
 * Target = 4:
 *   bs_first → 1  (index of first 4)
 *   bs_last  → 4  (index of last 4)
 *   count = last - first + 1 = 4
 *
 * g_result = (n << 16) | (first << 8) | count
 *           = (10 << 16) | (1 << 8) | 4 = 0x000A0104
 *
 * Recognizable decompiler idioms:
 *   int lo=0, hi=n-1; while(lo<=hi) { int mid=(lo+hi)/2; ... }  ← binary search frame
 *   if (arr[mid] == target) { result=mid; hi=mid-1; }            ← leftmost convergence
 *   if (arr[mid] == target) { result=mid; lo=mid+1; }            ← rightmost convergence
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Binary search: first (leftmost) occurrence ──────────────────────────── */

static int bs_first(const int *arr, int n, int target)
{
    int lo = 0, hi = n - 1, result = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (arr[mid] < target) {
            lo = mid + 1;
        } else if (arr[mid] > target) {
            hi = mid - 1;
        } else {
            result = mid;
            hi = mid - 1;   /* continue left to find first */
        }
    }
    return result;
}

/* ── Binary search: last (rightmost) occurrence ──────────────────────────── */

static int bs_last(const int *arr, int n, int target)
{
    int lo = 0, hi = n - 1, result = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (arr[mid] < target) {
            lo = mid + 1;
        } else if (arr[mid] > target) {
            hi = mid - 1;
        } else {
            result = mid;
            lo = mid + 1;   /* continue right to find last */
        }
    }
    return result;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_binary_search(void)
{
    static const int arr[10] = {2, 4, 4, 4, 4, 8, 12, 16, 20, 24};
    const int n      = 10;
    const int target = 4;

    int first = bs_first(arr, n, target);   /* = 1 */
    int last  = bs_last (arr, n, target);   /* = 4 */
    int count = (first >= 0 && last >= 0) ? last - first + 1 : 0; /* = 4 */

    g_result = ((uint32_t)n << 16)
             | ((uint32_t)first << 8)
             | ((uint32_t)count & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_binary_search();
    for (;;);
}
