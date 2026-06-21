/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Li Chao Tree (Minimum Linear Functions) fixture.
 *
 * A Li Chao tree stores a set of lines y=mx+b over integer x-domain [lo,hi].
 * Each node stores the "dominant" line — the one giving the minimum at the midpoint.
 * Queries return the minimum y-value over all inserted lines at a given x.
 *
 * Distinctive decompiler idioms:
 *   1. `if (!lc_has[nd]) { lc_m[nd]=m; lc_b[nd]=b; lc_has[nd]=1; return; }` — first insert
 *   2. `mid_new = (m*mid+b < lc_eval(nd,mid))` — midpoint dominance test
 *   3. `if (mid_new) { swap(stored, new); }` — store winner at mid
 *   4. `if (lo_new != mid_new) lc_add(left); else lc_add(right)` — recurse with loser
 *   5. `res = lc_has[nd] ? lc_eval(nd,x) : INF` — query over stored line
 *
 * Lines: y = 2x+1  (slope=2, intercept=1)
 *        y = -x+10 (slope=-1, intercept=10)
 *        y = x+3   (slope=1, intercept=3)
 *
 * Queries (minimum at x):
 *   x=1: min(3, 9, 4)   = 3   (line y=2x+1 wins)
 *   x=3: min(7, 7, 6)   = 6   (line y=x+3 wins)
 *   x=5: min(11, 5, 8)  = 5   (line y=-x+10 wins)
 *   sum = 3+6+5 = 14 = 0x0E
 *
 * n_queries  = 3  = 0x03
 * sum_min    = 14 = 0x0E
 * min_at_x5  = 5  = 0x05
 *
 * g_result = (n_queries << 16) | (sum_min << 8) | min_at_x5 = 0x030E05
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LC_LO 0
#define LC_HI 7
#define LC_SZ 64    /* 4*(LC_HI+1) for the segment tree */

static int lc_m[LC_SZ];
static int lc_b[LC_SZ];
static int lc_has[LC_SZ];

static int lc_eval(int nd, int x) { return lc_m[nd] * x + lc_b[nd]; }

static void lc_add(int nd, int lo, int hi, int m, int b)
{
    if (!lc_has[nd]) {
        lc_m[nd] = m; lc_b[nd] = b; lc_has[nd] = 1; return;
    }
    int mid    = (lo + hi) / 2;
    int lo_new  = (m * lo + b  < lc_eval(nd, lo));
    int mid_new = (m * mid + b < lc_eval(nd, mid));
    if (mid_new) {
        int tm = lc_m[nd], tb = lc_b[nd];
        lc_m[nd] = m; lc_b[nd] = b;
        m = tm; b = tb;
    }
    if (lo == hi) return;
    if (lo_new != mid_new) lc_add(2 * nd,     lo,      mid, m, b);
    else                   lc_add(2 * nd + 1,  mid + 1, hi,  m, b);
}

static int lc_query(int nd, int lo, int hi, int x)
{
    int res = lc_has[nd] ? lc_eval(nd, x) : 0x7FFFFFFF;
    if (lo == hi) return res;
    int mid = (lo + hi) / 2, child;
    if (x <= mid) child = lc_query(2 * nd,     lo,      mid, x);
    else          child = lc_query(2 * nd + 1,  mid + 1, hi,  x);
    return res < child ? res : child;
}

void test_li_chao(void)
{
    lc_add(1, LC_LO, LC_HI,  2,  1);
    lc_add(1, LC_LO, LC_HI, -1, 10);
    lc_add(1, LC_LO, LC_HI,  1,  3);

    int q1  = lc_query(1, LC_LO, LC_HI, 1);  /* 3  */
    int q3  = lc_query(1, LC_LO, LC_HI, 3);  /* 6  */
    int q5  = lc_query(1, LC_LO, LC_HI, 5);  /* 5  */
    int sum = q1 + q3 + q5;                   /* 14 */

    g_result = ((uint32_t)3   << 16)
             | ((uint32_t)sum << 8)
             | ((uint32_t)q5 & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_li_chao();
    for (;;);
}
