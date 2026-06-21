/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Shoelace Formula (Polygon Area) fixture.
 *
 * The Shoelace (Gauss area) formula computes signed 2× area of a simple
 * polygon from its vertex list in O(n):
 *
 *   2A = |Σ_{i=0}^{n-1} (x[j]*y[i] - x[i]*y[j])|   where j = (i+1) % n
 *
 * Distinctive decompiler idioms:
 *   1. `sum += vx[j]*vy[i] - vx[i]*vy[j]` — cross-product accumulation
 *   2. `j = (i + 1) % n` OR `for (i=0, j=n-1; i<n; j=i++)` — rotating pair
 *   3. Absolute-value normalization: `return sum < 0 ? -sum : sum`
 *
 * Test polygon — regular hexagon:
 *   Vertices: (0,4),(2,7),(6,7),(8,4),(6,1),(2,1)
 *   2 × Area  = 72 = 0x48
 *   Area      = 36 = 0x24
 *
 * g_result = (n_vertices << 16) | (two_area << 8) | area = 0x00064824
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SL_N 6

static const int sl_vx[SL_N] = {0, 2, 6, 8, 6, 2};
static const int sl_vy[SL_N] = {4, 7, 7, 4, 1, 1};

/* Returns twice the signed area (positive for CCW, negative for CW). */
static int shoelace_2x(void)
{
    int sum = 0, j = SL_N - 1;
    for (int i = 0; i < SL_N; j = i++) {
        sum += sl_vx[j] * sl_vy[i] - sl_vx[i] * sl_vy[j];
    }
    return sum < 0 ? -sum : sum;
}

void test_shoelace(void)
{
    int two_area = shoelace_2x();      /* 72 */
    int area     = two_area >> 1;      /* 36 */

    g_result = ((uint32_t)SL_N   << 16)
             | ((uint32_t)two_area << 8)
             | ((uint32_t)area & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_shoelace();
    for (;;);
}
