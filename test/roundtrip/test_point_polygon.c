/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Point-in-Polygon (Ray Casting) fixture.
 *
 * Ray casting algorithm: cast a ray rightward (+x) from the test point.
 * Count the number of polygon edges it crosses; odd = inside.
 *
 * Division-free integer formulation:
 *   Edge (xi,yi)-(xj,yj) crosses if (yi > py) != (yj > py).
 *   Intersection x = xj + (xi-xj)*(py-yj)/(yi-yj) > px
 *   Multiply out: (xi-xj)*(py-yj)  >(< if dy<0)  (px-xj)*(yi-yj)
 *
 * Distinctive decompiler idioms:
 *   1. `(vy[i] > py) != (vy[j] > py)` — crossing horizontal level test
 *   2. `dy > 0 ? (lhs > rhs) : (lhs < rhs)` — sign-flip to avoid division
 *   3. `inside ^= 1` — toggle parity of crossing count
 *   4. `for (i=0, j=n-1; i<n; j=i++)` — consecutive vertex pair idiom
 *
 * Polygon: axis-aligned square (0,0)-(6,0)-(6,6)-(0,6), 4 vertices.
 *
 * Test points (5 total):
 *   (3,3) → inside
 *   (7,3) → outside  (right of square)
 *   (1,1) → inside
 *   (3,7) → outside  (above square)
 *   (5,5) → inside
 *
 * inside_count = 3
 * sum_x_inside = 3 + 1 + 5 = 9
 *
 * g_result = (n_pts << 16) | (inside_count << 8) | sum_x_inside = 0x00050309
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PIP_N 4  /* polygon vertex count */

static const int pip_vx[PIP_N] = {0, 6, 6, 0};
static const int pip_vy[PIP_N] = {0, 0, 6, 6};

/* Returns 1 if (px,py) is strictly inside the polygon. */
static int point_in_polygon(int px, int py)
{
    int inside = 0;
    int j = PIP_N - 1;
    for (int i = 0; i < PIP_N; j = i++) {
        int xi = pip_vx[i], yi = pip_vy[i];
        int xj = pip_vx[j], yj = pip_vy[j];
        if ((yi > py) != (yj > py)) {
            int dy  = yi - yj;
            int lhs = (xi - xj) * (py - yj);
            int rhs = (px - xj) * dy;
            if (dy > 0 ? (lhs > rhs) : (lhs < rhs))
                inside ^= 1;
        }
    }
    return inside;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_point_polygon(void)
{
    static const int tx[] = {3, 7, 1, 3, 5};
    static const int ty[] = {3, 3, 1, 7, 5};

    int inside_count = 0, sum_x = 0;
    for (int k = 0; k < 5; k++) {
        if (point_in_polygon(tx[k], ty[k])) {
            inside_count++;
            sum_x += tx[k];
        }
    }
    /* inside_count=3, sum_x=9 */

    g_result = (5u << 16)
             | ((uint32_t)inside_count << 8)
             | (uint32_t)(sum_x & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_point_polygon();
    for (;;);
}
