/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Comb Sort fixture.
 *
 * Comb sort improves bubble sort by using a gap > 1 for early passes,
 * eliminating "turtles" (small elements near the end).
 *
 * Gap shrink factor ≈ 1.3, implemented in integer arithmetic as gap = gap*10/13.
 *
 * Distinctive decompiler idioms vs bubble sort:
 *   1. `gap = gap * 10 / 13` — integer 1.3 approximation (not gap--)
 *   2. `if (gap < 1) gap = 1` — floor guard
 *   3. Outer condition: `while (gap > 1 || !sorted)` (not just `while (!sorted)`)
 *   4. Inner comparisons stride by gap: `arr[i] > arr[i + gap]`
 *
 * Input  (n=7): {5, 2, 8, 1, 9, 3, 6}
 * Sorted (n=7): {1, 2, 3, 5, 6, 8, 9}
 *
 * n       = 7
 * last    = arr[n-1] = 9
 * xor_all = 1^2^3^5^6^8^9 = 2
 *
 * g_result = (n << 16) | (last << 8) | xor_all = 0x00070902
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Comb Sort ────────────────────────────────────────────────────────────── */

#define COMB_N 7

static int comb_arr[COMB_N];

static void comb_sort(int *arr, int n)
{
    int gap = n, sorted = 0;
    while (gap > 1 || !sorted) {
        gap = gap * 10 / 13;
        if (gap < 1) gap = 1;
        sorted = 1;
        for (int i = 0; i + gap < n; i++) {
            if (arr[i] > arr[i + gap]) {
                int tmp = arr[i]; arr[i] = arr[i + gap]; arr[i + gap] = tmp;
                sorted = 0;
            }
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_comb_sort(void)
{
    static const int src[COMB_N] = {5, 2, 8, 1, 9, 3, 6};
    for (int i = 0; i < COMB_N; i++) comb_arr[i] = src[i];

    comb_sort(comb_arr, COMB_N);
    /* sorted: {1,2,3,5,6,8,9} */

    uint32_t xor_all = 0;
    for (int i = 0; i < COMB_N; i++) xor_all ^= (uint32_t)comb_arr[i];

    g_result = ((uint32_t)COMB_N << 16)
             | ((uint32_t)comb_arr[COMB_N - 1] << 8)
             | (xor_all & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_comb_sort();
    for (;;);
}
