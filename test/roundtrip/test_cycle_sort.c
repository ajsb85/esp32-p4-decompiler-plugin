/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Cycle Sort fixture.
 *
 * Cycle sort minimizes the number of memory writes (O(n) writes) by placing
 * each element into its final position in one write, cycling through the
 * elements displaced.
 *
 * Distinctive decompiler idioms:
 *   1. Outer `cycleStart` loop: for (cs = 0; cs < n-1; cs++)
 *   2. Position counting: `for (i=cs+1; i<n; i++) if (arr[i]<item) pos++`
 *   3. Skip-duplicates inner loop: `while (item == arr[pos]) pos++`
 *   4. Nested cycle-rotation: `while (pos != cs)` with re-count inside
 *   5. Explicit `writes++` counter (separates from swap-heavy sorts)
 *
 * Input (n=5): {3, 1, 5, 4, 2}
 * Sorted:      {1, 2, 3, 4, 5}
 *
 * Cycle trace:
 *   cs=0: item=3→pos=2, write 3→arr[2](=5), item=5→pos=4, write 5→arr[4](=2),
 *           item=2→pos=1, write 2→arr[1](=1), item=1→pos=0, write 1→arr[0](=3) (4 writes)
 *   cs=1..3: already in place
 *
 * writes  = 4
 * xor_all = 1^2^3^4^5 = 1
 *
 * g_result = (n << 16) | (writes << 8) | xor_all = 0x00050401
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Cycle Sort ──────────────────────────────────────────────────────────── */

#define CY_N 5

static int cy_arr[CY_N];

static int cycle_sort(int *arr, int n)
{
    int writes = 0;
    for (int cs = 0; cs < n - 1; cs++) {
        int item = arr[cs];
        int pos  = cs;
        for (int i = cs + 1; i < n; i++)
            if (arr[i] < item) pos++;
        if (pos == cs) continue;

        while (item == arr[pos]) pos++;
        int tmp = arr[pos]; arr[pos] = item; item = tmp;
        writes++;

        while (pos != cs) {
            pos = cs;
            for (int i = cs + 1; i < n; i++)
                if (arr[i] < item) pos++;
            while (item == arr[pos]) pos++;
            tmp = arr[pos]; arr[pos] = item; item = tmp;
            writes++;
        }
    }
    return writes;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_cycle_sort(void)
{
    static const int src[CY_N] = {3, 1, 5, 4, 2};
    for (int i = 0; i < CY_N; i++) cy_arr[i] = src[i];

    int writes = cycle_sort(cy_arr, CY_N);
    /* sorted: {1,2,3,4,5}, writes=4 */

    uint32_t xor_all = 0;
    for (int i = 0; i < CY_N; i++) xor_all ^= (uint32_t)cy_arr[i];

    g_result = ((uint32_t)CY_N << 16)
             | ((uint32_t)writes << 8)
             | (xor_all & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_cycle_sort();
    for (;;);
}
