/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Convex Hull (Graham Scan) fixture.
 *
 * Graham scan: find the smallest convex polygon containing all input points.
 * 1. Anchor at the lowest-leftmost point.
 * 2. Sort remaining points by polar angle from the anchor.
 * 3. Traverse sorted points; pop stack while cross product ≤ 0 (not left turn).
 *
 * Distinctive decompiler idioms:
 *   1. `cross(O,A,B) = (A.x-O.x)*(B.y-O.y) - (A.y-O.y)*(B.x-O.x)` — CCW test
 *   2. `while (top >= 2 && cross(hull[top-2], hull[top-1], p) <= 0) top--`
 *   3. `hull[top++] = i` — push accepted point index
 *   4. Selection sort by polar angle using cross product comparator
 *
 * Input: 6 points — (0,0),(2,0),(3,1),(2,2),(0,2),(1,1)
 *
 * Convex hull (CCW from anchor):
 *   (0,0) → (2,0) → (3,1) → (2,2) → (0,2)  — 5 points
 *   Interior point (1,1) is correctly excluded.
 *
 * hull_size = 5
 * sum_x     = 0+2+3+2+0 = 7
 * sum_y     = 0+0+1+2+2 = 5
 *
 * g_result = (hull_size << 16) | (sum_x << 8) | sum_y = 0x00050705
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Points ───────────────────────────────────────────────────────────────── */

#define CH_N 6

static int ch_px[CH_N] = {0, 2, 3, 2, 0, 1};
static int ch_py[CH_N] = {0, 0, 1, 2, 2, 1};

static int ch_hull[CH_N];
static int ch_htop;

/* ── Cross product (O→A × O→B, positive = left turn) ────────────────────── */

static int ch_cross(int oi, int ai, int bi)
{
    return (ch_px[ai] - ch_px[oi]) * (ch_py[bi] - ch_py[oi])
         - (ch_py[ai] - ch_py[oi]) * (ch_px[bi] - ch_px[oi]);
}

/* ── Graham Scan ─────────────────────────────────────────────────────────── */

static void graham_scan(void)
{
    /* Find lowest-leftmost anchor */
    int mi = 0;
    for (int i = 1; i < CH_N; i++)
        if (ch_py[i] < ch_py[mi] || (ch_py[i] == ch_py[mi] && ch_px[i] < ch_px[mi]))
            mi = i;

    /* Swap anchor to index 0 */
    int tx = ch_px[0]; ch_px[0] = ch_px[mi]; ch_px[mi] = tx;
    int ty = ch_py[0]; ch_py[0] = ch_py[mi]; ch_py[mi] = ty;

    /* Selection sort by polar angle from anchor; ties: farthest point last */
    for (int i = 1; i < CH_N - 1; i++) {
        int bst = i;
        for (int j = i + 1; j < CH_N; j++) {
            int c = ch_cross(0, bst, j);
            if (c < 0) {
                bst = j;
            } else if (c == 0) {
                int d1 = (ch_px[bst]-ch_px[0])*(ch_px[bst]-ch_px[0])
                       + (ch_py[bst]-ch_py[0])*(ch_py[bst]-ch_py[0]);
                int d2 = (ch_px[j]-ch_px[0])*(ch_px[j]-ch_px[0])
                       + (ch_py[j]-ch_py[0])*(ch_py[j]-ch_py[0]);
                if (d2 > d1) bst = j;
            }
        }
        if (bst != i) {
            tx = ch_px[i]; ch_px[i] = ch_px[bst]; ch_px[bst] = tx;
            ty = ch_py[i]; ch_py[i] = ch_py[bst]; ch_py[bst] = ty;
        }
    }

    /* Graham stack */
    ch_htop = 0;
    for (int i = 0; i < CH_N; i++) {
        while (ch_htop >= 2 && ch_cross(ch_hull[ch_htop-2], ch_hull[ch_htop-1], i) <= 0)
            ch_htop--;
        ch_hull[ch_htop++] = i;
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_convex_hull(void)
{
    graham_scan();

    int sx = 0, sy = 0;
    for (int i = 0; i < ch_htop; i++) {
        sx += ch_px[ch_hull[i]];
        sy += ch_py[ch_hull[i]];
    }

    /* hull_size=5, sum_x=7, sum_y=5 */
    g_result = ((uint32_t)ch_htop << 16)
             | ((uint32_t)(sx & 0xFF) << 8)
             | (uint32_t)(sy & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_convex_hull();
    for (;;);
}
