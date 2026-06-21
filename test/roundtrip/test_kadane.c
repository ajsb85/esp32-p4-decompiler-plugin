/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Kadane's maximum-subarray-sum algorithm fixture.
 *
 * Kadane's O(n) maximum subarray sum with start/end index tracking.
 * Two very distinctive idioms:
 *
 *   1. Reset-or-extend:
 *        if (cur_sum + arr[i] > arr[i])  cur_sum += arr[i];
 *        else                             { cur_sum = arr[i]; tmp_start = i; }
 *
 *   2. Global-max update:
 *        if (cur_sum > max_sum)  { max_sum=cur_sum; start=tmp_start; end=i; }
 *
 * Input (n=9): {-2, 1, -3, 4, -1, 2, 1, -5, 4}  (classic benchmark array)
 *
 * Maximum subarray: arr[3..6] = {4, -1, 2, 1}
 *   max_sum = 6
 *   start   = 3
 *   end     = 6
 *   n       = 9
 *
 * g_result = (n << 16) | (max_sum << 8) | ((start << 4) | end)
 *          = 0x00090636
 *
 * Recognizable decompiler idioms:
 *   if (cur_sum + arr[i] > arr[i]) cur_sum += arr[i];   ← extend vs restart
 *   if (cur_sum > max_sum) { max_sum = cur_sum; ... }   ← global max update
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Kadane ───────────────────────────────────────────────────────────────── */

#define KAD_N 9

static int kadane(const int *arr, int n, int *out_start, int *out_end)
{
    int max_sum = arr[0], cur_sum = arr[0];
    int tmp_start = 0, ms = 0, me = 0;

    for (int i = 1; i < n; i++) {
        if (cur_sum + arr[i] > arr[i]) {
            cur_sum += arr[i];
        } else {
            cur_sum   = arr[i];
            tmp_start = i;
        }
        if (cur_sum > max_sum) {
            max_sum = cur_sum;
            ms      = tmp_start;
            me      = i;
        }
    }
    *out_start = ms;
    *out_end   = me;
    return max_sum;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_kadane(void)
{
    static const int arr[KAD_N] = {-2, 1, -3, 4, -1, 2, 1, -5, 4};
    int start, end;
    int max_sum = kadane(arr, KAD_N, &start, &end);   /* = 6, [3,6] */

    g_result = ((uint32_t)KAD_N << 16)
             | ((uint32_t)max_sum << 8)
             | (((uint32_t)start << 4) | (uint32_t)end);
}

__attribute__((noreturn)) void _start(void)
{
    test_kadane();
    for (;;);
}
