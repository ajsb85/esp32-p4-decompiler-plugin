/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — In-place Quicksort (Lomuto) round-trip fixture.
 *
 * Exercises divide-and-conquer recursion with an in-place partition swap.
 * The Lomuto partition idiom (pivot = a[hi]; scan with two indices; swap at
 * the end) is highly recognizable in decompiled output.
 *
 * Input: {5, 3, 8, 1, 7, 2, 9, 4, 6} (9 distinct elements)
 * After sort: {1, 2, 3, 4, 5, 6, 7, 8, 9}
 *
 * XOR of sorted: 1^2^3^4^5^6^7^8^9
 *   1^2=3, ^3=0, ^4=4, ^5=1, ^6=7, ^7=0, ^8=8, ^9=1  → XOR=1
 * Sum of sorted: 1+2+...+9 = 45 = 0x2D
 * n = 9
 *
 * g_result = (n << 16) | (sum << 8) | xor = 0x00092D01
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Lomuto partition ────────────────────────────────────────────────────── */

static int qs_partition(int *a, int lo, int hi)
{
    int pivot = a[hi];
    int i     = lo - 1;
    for (int j = lo; j < hi; j++) {
        if (a[j] <= pivot) {
            i++;
            int tmp = a[i]; a[i] = a[j]; a[j] = tmp;
        }
    }
    int tmp = a[i + 1]; a[i + 1] = a[hi]; a[hi] = tmp;
    return i + 1;
}

/* ── Recursive quicksort ─────────────────────────────────────────────────── */

static void quicksort(int *a, int lo, int hi)
{
    if (lo < hi) {
        int p = qs_partition(a, lo, hi);
        quicksort(a, lo, p - 1);
        quicksort(a, p + 1, hi);
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_quicksort(void)
{
    int a[9] = {5, 3, 8, 1, 7, 2, 9, 4, 6};

    quicksort(a, 0, 8);

    uint32_t xr = 0, s = 0;
    for (int i = 0; i < 9; i++) {
        xr ^= (uint32_t)a[i];
        s  += (uint32_t)a[i];
    }

    g_result = (9u << 16) | (s << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_quicksort();
    for (;;);
}
