/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Trapping Rain Water (Two-Pointer) fixture.
 *
 * Computes total water trapped after raining using O(1)-space two-pointer
 * technique: maintain left/right max-height walls, advance the shorter side.
 *
 * Distinctive decompiler idioms:
 *   1. Dual pointer converge: `while (left < right)` with BOTH pointers moving
 *   2. `if (h[left] < h[right])` branch decides which side to advance
 *   3. `maxL = h[left] > maxL ? h[left] : maxL` — running max without array
 *   4. `water += maxL - h[left]` — accumulation on the shorter side
 *   5. Pattern structurally identical in both branches (left vs right symmetric)
 *
 * Input (n=6): {4, 2, 0, 3, 2, 5}
 *
 * Water per bar:
 *   bar 0: h=4 → max_L=4, no water
 *   bar 1: h=2 → water += 4-2 = 2
 *   bar 2: h=0 → water += 4-0 = 4
 *   bar 3: h=3 → water += 4-3 = 1
 *   bar 4: h=2 → water += 4-2 = 2
 *   bar 5: h=5 → max_R=5, no water
 *
 * n     = 6
 * water = 9
 * xor_h = 4^2^0^3^2^5 = 2
 *
 * g_result = (n << 16) | (water << 8) | xor_h = 0x00060902
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Trapping Rain Water ─────────────────────────────────────────────────── */

#define RAIN_N 6

static const int rain_h[RAIN_N] = {4, 2, 0, 3, 2, 5};

static int trap_rain(const int *h, int n)
{
    int left = 0, right = n - 1;
    int max_l = 0, max_r = 0, water = 0;
    while (left < right) {
        if (h[left] < h[right]) {
            if (h[left] >= max_l) max_l = h[left];
            else                  water += max_l - h[left];
            left++;
        } else {
            if (h[right] >= max_r) max_r = h[right];
            else                   water += max_r - h[right];
            right--;
        }
    }
    return water;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_trapping_rain(void)
{
    int water = trap_rain(rain_h, RAIN_N);
    /* water = 9 */

    uint32_t xor_h = 0;
    for (int i = 0; i < RAIN_N; i++) xor_h ^= (uint32_t)rain_h[i];

    g_result = ((uint32_t)RAIN_N << 16)
             | ((uint32_t)water << 8)
             | (xor_h & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_trapping_rain();
    for (;;);
}
