/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Line Segment Intersection fixture.
 *
 * Tests whether two line segments AB and CD properly intersect using
 * signed 2-D cross products (no floating point required).
 *
 * Algorithm (proper intersection only; collinear cases excluded):
 *   d1 = cross(B-A, C-A)
 *   d2 = cross(B-A, D-A)
 *   d3 = cross(D-C, A-C)
 *   d4 = cross(D-C, B-C)
 *   intersect ↔ sign(d1)≠sign(d2) ∧ sign(d3)≠sign(d4)
 *
 * Distinctive decompiler idioms:
 *   1. cross2d(ax,ay, bx,by) = ax*by - ay*bx  — inline 2-D wedge product
 *   2. sign(x) = (x>0)-(x<0)  — branch-free signum idiom on RISC-V
 *   3. Chain of integer multiplications with no division or sqrt
 *
 * Five test pairs:
 *   1. (0,0)-(6,6) vs (0,6)-(6,0)  →  INTERSECT   (cross at (3,3))
 *   2. (0,0)-(3,0) vs (0,1)-(3,1)  →  NO INTERSECT (parallel horizontal)
 *   3. (0,0)-(0,6) vs (1,0)-(1,6)  →  NO INTERSECT (parallel vertical)
 *   4. (2,0)-(2,6) vs (0,3)-(6,3)  →  INTERSECT   (cross at (2,3))
 *   5. (0,0)-(4,4) vs (2,0)-(0,2)  →  INTERSECT   (cross at (1,1))
 *
 * n_pairs      = 5
 * count_yes    = 3
 * count_no     = 2
 *
 * g_result = (n_pairs << 16) | (count_yes << 8) | count_no = 0x00050302
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── 2-D cross product of vectors (ax,ay) and (bx,by) ───────────────────── */

static int cross2d(int ax, int ay, int bx, int by)
{
    return ax * by - ay * bx;
}

static int sign_of(int x)
{
    return (x > 0) - (x < 0);
}

/* Returns 1 if segments AB and CD properly intersect, 0 otherwise. */
static int seg_intersect(int ax, int ay, int bx, int by,
                         int cx, int cy, int dx, int dy)
{
    int d1 = cross2d(bx - ax, by - ay, cx - ax, cy - ay);
    int d2 = cross2d(bx - ax, by - ay, dx - ax, dy - ay);
    int d3 = cross2d(dx - cx, dy - cy, ax - cx, ay - cy);
    int d4 = cross2d(dx - cx, dy - cy, bx - cx, by - cy);

    if (sign_of(d1) != sign_of(d2) && d1 != 0 && d2 != 0 &&
        sign_of(d3) != sign_of(d4) && d3 != 0 && d4 != 0)
        return 1;
    return 0;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_line_intersection(void)
{
    /* ax ay bx by  cx cy dx dy */
    static const int segs[5][8] = {
        {0,0, 6,6,  0,6, 6,0},  /* INTERSECT  */
        {0,0, 3,0,  0,1, 3,1},  /* NO INTERSECT */
        {0,0, 0,6,  1,0, 1,6},  /* NO INTERSECT */
        {2,0, 2,6,  0,3, 6,3},  /* INTERSECT  */
        {0,0, 4,4,  2,0, 0,2},  /* INTERSECT  */
    };

    int count_yes = 0, count_no = 0;
    for (int i = 0; i < 5; i++) {
        if (seg_intersect(segs[i][0], segs[i][1], segs[i][2], segs[i][3],
                          segs[i][4], segs[i][5], segs[i][6], segs[i][7])) {
            count_yes++;
        } else {
            count_no++;
        }
    }
    /* count_yes=3, count_no=2 */

    g_result = (5u << 16)
             | ((uint32_t)count_yes << 8)
             | (uint32_t)count_no;
}

__attribute__((noreturn)) void _start(void)
{
    test_line_intersection();
    for (;;);
}
