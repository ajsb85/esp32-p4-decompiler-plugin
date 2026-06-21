/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Shell Sort (gap-halving) fixture.
 *
 * Shell sort is a generalization of insertion sort that allows exchanges of
 * elements far apart, using progressively decreasing gap sizes.
 *
 * Algorithm (shell/ciura simplified with gap = n/2, gap /= 2):
 *   for (gap = n/2; gap > 0; gap /= 2):
 *     for (i = gap; i < n; i++):
 *       tmp = arr[i]; j = i;
 *       while (j >= gap && arr[j-gap] > tmp): arr[j] = arr[j-gap]; j -= gap;
 *       arr[j] = tmp;
 *
 * Distinctive decompiler idioms:
 *   1. Outer gap loop: gap = n/2; ...; gap /= 2
 *   2. Inner: j -= gap (not j-- like regular insertion sort)
 *   3. arr[j] = arr[j-gap]; j -= gap  ← gap-strided shift
 *
 * Input (n=8): {8, 3, 7, 1, 5, 2, 9, 4}
 * Sorted:      {1, 2, 3, 4, 5, 7, 8, 9}
 *
 * n        = 8
 * last     = arr[n-1] = 9
 * xor_all  = 1^2^3^4^5^7^8^9 = 7
 *
 * g_result = (n << 16) | (last << 8) | xor_all = 0x00080907
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Shell Sort ───────────────────────────────────────────────────────────── */

#define SHELL_N 8

static int shell_arr[SHELL_N];

static void shell_sort(int *arr, int n)
{
    for (int gap = n / 2; gap > 0; gap /= 2) {
        for (int i = gap; i < n; i++) {
            int tmp = arr[i];
            int j = i;
            while (j >= gap && arr[j - gap] > tmp) {
                arr[j] = arr[j - gap];
                j -= gap;
            }
            arr[j] = tmp;
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_shell_sort(void)
{
    static const int src[SHELL_N] = {8, 3, 7, 1, 5, 2, 9, 4};
    for (int i = 0; i < SHELL_N; i++) shell_arr[i] = src[i];

    shell_sort(shell_arr, SHELL_N);
    /* sorted: {1,2,3,4,5,7,8,9} */

    uint32_t xor_all = 0;
    for (int i = 0; i < SHELL_N; i++) xor_all ^= (uint32_t)shell_arr[i];

    g_result = ((uint32_t)SHELL_N << 16)
             | ((uint32_t)shell_arr[SHELL_N - 1] << 8)
             | (xor_all & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_shell_sort();
    for (;;);
}
