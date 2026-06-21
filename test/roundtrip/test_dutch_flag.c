/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Dutch National Flag (3-way partition) fixture.
 *
 * Dijkstra's 3-way partition using three pointers lo/mid/hi.
 * In one pass (while mid <= hi) the array is partitioned into three regions:
 *
 *   arr[0..lo-1]  < pivot
 *   arr[lo..mid-1] == pivot
 *   arr[hi+1..n-1] > pivot
 *
 * Three-branch idiom:
 *   if arr[mid] < pivot: swap(arr[lo], arr[mid]); lo++; mid++;
 *   elif arr[mid] == pivot: mid++;
 *   else: swap(arr[mid], arr[hi]); hi--;
 *
 * Input (n=6): {2, 0, 2, 1, 1, 0},  pivot = 1
 *
 * After partition: {0, 0, 1, 1, 2, 2}
 *   lo = 2  (index of first '1')
 *   mid = 4  (index past last '1', i.e., first '2')
 *
 * g_result = (n << 16) | (lo << 8) | mid = 0x00060204
 *
 * Recognizable decompiler idioms:
 *   while (mid <= hi) { ... } ← single-pass 3-way
 *   swap(arr[lo], arr[mid]); lo++; mid++ ← less-than branch
 *   swap(arr[mid], arr[hi]); hi--       ← greater-than branch
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── DNF 3-way partition ─────────────────────────────────────────────────── */

#define DNF_N 6

static int dnf_arr[DNF_N];

static void dnf_partition(int pivot, int *out_lo, int *out_mid)
{
    int lo = 0, mid = 0, hi = DNF_N - 1;

    while (mid <= hi) {
        if (dnf_arr[mid] < pivot) {
            int tmp      = dnf_arr[lo];
            dnf_arr[lo]  = dnf_arr[mid];
            dnf_arr[mid] = tmp;
            lo++;
            mid++;
        } else if (dnf_arr[mid] == pivot) {
            mid++;
        } else {
            int tmp      = dnf_arr[mid];
            dnf_arr[mid] = dnf_arr[hi];
            dnf_arr[hi]  = tmp;
            hi--;
        }
    }
    *out_lo  = lo;   /* first == pivot */
    *out_mid = mid;  /* first > pivot  */
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_dutch_flag(void)
{
    static const int src[DNF_N] = {2, 0, 2, 1, 1, 0};
    for (int i = 0; i < DNF_N; i++) dnf_arr[i] = src[i];

    int lo, mid;
    dnf_partition(1, &lo, &mid);   /* lo=2, mid=4 */

    g_result = ((uint32_t)DNF_N << 16)
             | ((uint32_t)lo << 8)
             | ((uint32_t)mid & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_dutch_flag();
    for (;;);
}
