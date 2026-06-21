/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Sliding Window Maximum (monotonic deque) fixture.
 *
 * For each window of size w in an array, find the maximum element.
 * O(n) via a monotonic decreasing deque of indices:
 *
 *   for i = 0..n-1:
 *     while deque not empty && arr[deq_back] <= arr[i]: pop_back
 *     push_back(i)
 *     while deq_front < i - w + 1: pop_front    ← evict stale entries
 *     if i >= w-1: max[i-w+1] = arr[deq_front]
 *
 * Distinctive decompiler idioms:
 *   1. Circular deque with head/tail indices
 *   2. Pop-back while arr[deq[tail-1]] <= arr[i]  (maintain decreasing)
 *   3. Pop-front while deq[head] < i-w+1           (evict outside window)
 *   4. Assign max from arr[deq[head]]
 *
 * Input: arr={1,3,-1,-3,5,3,6,7}, n=8, w=3
 *
 * Window maxima:
 *   [1,3,-1]  → 3
 *   [3,-1,-3] → 3
 *   [-1,-3,5] → 5
 *   [-3,5,3]  → 5
 *   [5,3,6]   → 6
 *   [3,6,7]   → 7
 *
 * n_windows = n - w + 1 = 6
 * sum_max   = 3+3+5+5+6+7 = 29  (0x1D)
 * xor_max   = 3^3^5^5^6^7 = 1
 *
 * g_result = (n << 16) | (sum_max << 8) | xor_max = 0x00081D01
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Sliding Window Maximum ───────────────────────────────────────────────── */

#define SW_N   8
#define SW_W   3

static int sw_deq[SW_N];   /* index deque */
static int sw_max[SW_N];   /* results */

static void sliding_window_max(const int *arr, int n, int w)
{
    int head = 0, tail = 0;
    for (int i = 0; i < n; i++) {
        /* pop stale front */
        while (head < tail && sw_deq[head] < i - w + 1)
            head++;
        /* maintain decreasing: pop back while arr[back] <= arr[i] */
        while (head < tail && arr[sw_deq[tail - 1]] <= arr[i])
            tail--;
        sw_deq[tail++] = i;
        if (i >= w - 1)
            sw_max[i - w + 1] = arr[sw_deq[head]];
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_sliding_window(void)
{
    static const int arr[SW_N] = {1, 3, -1, -3, 5, 3, 6, 7};
    int n_wins = SW_N - SW_W + 1;

    sliding_window_max(arr, SW_N, SW_W);

    uint32_t sum_m = 0, xor_m = 0;
    for (int i = 0; i < n_wins; i++) {
        sum_m += (uint32_t)sw_max[i];
        xor_m ^= (uint32_t)sw_max[i];
    }
    /* sum=29, xor=1 */
    g_result = ((uint32_t)SW_N << 16) | (sum_m << 8) | (xor_m & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_sliding_window();
    for (;;);
}
