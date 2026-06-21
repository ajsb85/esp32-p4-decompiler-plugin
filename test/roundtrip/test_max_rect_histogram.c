/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Max Rectangle in Histogram fixture.
 *
 * Finds the largest rectangle that fits inside a histogram using a monotonic
 * stack.  When a shorter bar is encountered, pop taller bars and compute the
 * area each could extend backwards to.
 *
 * Distinctive decompiler idioms:
 *   1. `mrh_stk[]` monotonic increasing stack of bar indices
 *   2. Pop loop: `while (top >= 0 && h[mrh_stk[top]] >= h[i])` on new bar
 *   3. Width formula: `width = (top < 0) ? i : i - mrh_stk[top] - 1`
 *   4. Final drain: `while (top >= 0)` after processing all bars
 *
 * Input heights (n=6): {2, 1, 5, 6, 2, 3}
 *
 * Area trace (largest first):
 *   Height 5, width 2 → area 10  (bars 2..3)
 *   Height 2, width 4 → area  8  (bars 1..4)
 *   Height 6, width 1 → area  6  (bar 3)
 *
 * n        = 6
 * max_area = 10
 * xor_h    = 2^1^5^6^2^3 = 1
 *
 * g_result = (n << 16) | (max_area << 8) | xor_h = 0x00060A01
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Max Rectangle in Histogram ──────────────────────────────────────────── */

#define MRH_N 6

static const int mrh_h[MRH_N] = {2, 1, 5, 6, 2, 3};
static int mrh_stk[MRH_N + 1];

static int max_rect_histogram(const int *h, int n)
{
    int top = -1, max_area = 0;
    for (int i = 0; i <= n; i++) {
        int cur = (i == n) ? 0 : h[i];
        while (top >= 0 && h[mrh_stk[top]] >= cur) {
            int ht    = h[mrh_stk[top--]];
            int width = (top < 0) ? i : i - mrh_stk[top] - 1;
            int area  = ht * width;
            if (area > max_area) max_area = area;
        }
        mrh_stk[++top] = i;
    }
    return max_area;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_max_rect_histogram(void)
{
    int max_area = max_rect_histogram(mrh_h, MRH_N);
    /* max_area = 10 */

    uint32_t xor_h = 0;
    for (int i = 0; i < MRH_N; i++) xor_h ^= (uint32_t)mrh_h[i];

    g_result = ((uint32_t)MRH_N << 16)
             | ((uint32_t)max_area << 8)
             | (xor_h & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_max_rect_histogram();
    for (;;);
}
