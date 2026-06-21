/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Merge Sort round-trip fixture.
 *
 * Stable top-down merge sort using a static temporary buffer.
 * Recognizable decompiler idioms:
 *   mid = (lo + hi) / 2    (halving)
 *   two-pointer merge loop into tmp[]
 *   memcpy-back from tmp[] to a[]
 *
 * Input: {9, 2, 7, 1, 5, 3, 8, 4, 6, 0}  (10 elements, values 0-9)
 * After sort: {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
 *   XOR = 0^1^2^3^4^5^6^7^8^9 = 1
 *   sum = 0+1+...+9 = 45 = 0x2D
 *   n   = 10 = 0x0A
 *
 * g_result = (n << 16) | (sum << 8) | xor = 0x000A2D01
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Merge step ─────────────────────────────────────────────────────────── */

static int ms_tmp[16]; /* temporary buffer; max size = input length */

static void merge_step(int *a, int lo, int mid, int hi)
{
    int i = lo, j = mid + 1, k = lo;

    while (i <= mid && j <= hi)
        ms_tmp[k++] = (a[i] <= a[j]) ? a[i++] : a[j++];
    while (i <= mid) ms_tmp[k++] = a[i++];
    while (j <= hi)  ms_tmp[k++] = a[j++];

    for (int x = lo; x <= hi; x++)
        a[x] = ms_tmp[x];
}

/* ── Recursive merge sort ────────────────────────────────────────────────── */

static void mergesort(int *a, int lo, int hi)
{
    if (lo < hi) {
        int mid = (lo + hi) / 2;
        mergesort(a, lo, mid);
        mergesort(a, mid + 1, hi);
        merge_step(a, lo, mid, hi);
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_mergesort(void)
{
    int a[10] = {9, 2, 7, 1, 5, 3, 8, 4, 6, 0};

    mergesort(a, 0, 9);

    uint32_t xr = 0, s = 0;
    for (int i = 0; i < 10; i++) {
        xr ^= (uint32_t)a[i];
        s  += (uint32_t)a[i];
    }

    g_result = (10u << 16) | (s << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_mergesort();
    for (;;);
}
