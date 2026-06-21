/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Top-K Elements via Fixed-Size Min-Heap fixture.
 *
 * Maintains a min-heap of at most k elements while scanning an array.
 * After scanning, the heap contains the k largest elements.
 * This is a classic streaming top-k algorithm.
 *
 * Algorithm:
 *   For each element x in the stream:
 *     If heap size < k: insert x
 *     Else if x > heap_min: replace heap_min with x, sift down
 *
 * Distinctive decompiler idioms:
 *   1. `if (tk_hsz < K)` — fill phase with simple insert
 *   2. `if (x > tk_heap[0]) { tk_heap[0] = x; sift_down(); }` — evict minimum
 *   3. Sift-down: `while (child < sz) { sel=child; if (r<sz && h[r]<h[l]) sel=r; }`
 *   4. Heap[0] = minimum element (min-heap for max-k extraction)
 *
 * Input: array [3, 1, 4, 1, 5, 9, 2, 6, 5, 3], k=4
 *   Top 4 elements: {9, 6, 5, 5}
 *   Min of top-4: 5
 *   Sum of top-4: 25 = 0x19
 *
 * k          = 4  = 0x04
 * sum_top_k  = 25 = 0x19
 * min_top_k  = 5  = 0x05
 *
 * g_result = (k << 16) | (sum_top_k << 8) | min_top_k = 0x00041905
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TK_K 4

static int tk_heap[TK_K];
static int tk_hsz;

static void tk_sift_down(void)
{
    int i = 0;
    while (1) {
        int l = 2*i + 1, r = 2*i + 2, s = i;
        if (l < tk_hsz && tk_heap[l] < tk_heap[s]) s = l;
        if (r < tk_hsz && tk_heap[r] < tk_heap[s]) s = r;
        if (s == i) break;
        int t = tk_heap[s]; tk_heap[s] = tk_heap[i]; tk_heap[i] = t;
        i = s;
    }
}

static void tk_sift_up(int i)
{
    while (i > 0) {
        int p = (i - 1) / 2;
        if (tk_heap[p] <= tk_heap[i]) break;
        int t = tk_heap[p]; tk_heap[p] = tk_heap[i]; tk_heap[i] = t;
        i = p;
    }
}

static void tk_insert(int x)
{
    if (tk_hsz < TK_K) {
        tk_heap[tk_hsz++] = x;
        tk_sift_up(tk_hsz - 1);
    } else if (x > tk_heap[0]) {
        tk_heap[0] = x;
        tk_sift_down();
    }
}

void test_topk_heap(void)
{
    static const int arr[] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3};
    static const int n = 10;

    for (int i = 0; i < n; i++) tk_insert(arr[i]);

    int sum = 0;
    for (int i = 0; i < TK_K; i++) sum += tk_heap[i];
    int min_k = tk_heap[0];  /* min of top-k = heap root */

    /* k=4, sum=25, min=5 */
    g_result = ((uint32_t)TK_K  << 16)
             | ((uint32_t)sum   << 8)
             | ((uint32_t)min_k & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_topk_heap();
    for (;;);
}
