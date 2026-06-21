/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Min-heap (priority queue) round-trip fixture.
 *
 * Exercises a binary min-heap using the standard array representation
 * (parent = (i-1)/2, left = 2i+1, right = 2i+2) with sift-up / sift-down
 * invariant maintenance.
 *
 * Insertion order: {5, 3, 8, 1, 7, 2, 9, 4}
 * Extract-min order (heap sort): {1, 2, 3, 4, 5, 7, 8, 9}
 *
 * Accumulated values over all extracted elements:
 *   extract_xor = 1^2^3^4^5^7^8^9 = 0x07
 *   extract_sum = 1+2+3+4+5+7+8+9 = 39 = 0x27
 *
 * g_result = (extract_sum << 8) | (extract_xor & 0xFF) = 0x00002707
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Min-heap ─────────────────────────────────────────────────────────────── */

#define HEAP_MAX 16

static int  heap_arr[HEAP_MAX];
static int  heap_sz;

static void heap_swap(int i, int j)
{
    int t = heap_arr[i];
    heap_arr[i] = heap_arr[j];
    heap_arr[j] = t;
}

static void sift_up(int i)
{
    while (i > 0) {
        int p = (i - 1) / 2;
        if (heap_arr[p] > heap_arr[i]) {
            heap_swap(p, i);
            i = p;
        } else {
            break;
        }
    }
}

static void sift_down(int i)
{
    while (1) {
        int l = 2 * i + 1;
        int r = 2 * i + 2;
        int m = i;
        if (l < heap_sz && heap_arr[l] < heap_arr[m]) m = l;
        if (r < heap_sz && heap_arr[r] < heap_arr[m]) m = r;
        if (m == i) break;
        heap_swap(i, m);
        i = m;
    }
}

static void heap_insert(int v)
{
    heap_arr[heap_sz++] = v;
    sift_up(heap_sz - 1);
}

static int heap_extract_min(void)
{
    int min = heap_arr[0];
    heap_arr[0] = heap_arr[--heap_sz];
    if (heap_sz > 0) sift_down(0);
    return min;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_heap(void)
{
    static const int vals[8] = {5, 3, 8, 1, 7, 2, 9, 4};
    uint32_t xor_acc = 0;
    uint32_t sum_acc = 0;

    heap_sz = 0;

    for (int i = 0; i < 8; i++)
        heap_insert(vals[i]);

    for (int i = 0; i < 8; i++) {
        int v = heap_extract_min();
        xor_acc ^= (uint32_t)v;
        sum_acc  += (uint32_t)v;
    }

    g_result = (sum_acc << 8) | (xor_acc & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_heap();
    for (;;);
}
