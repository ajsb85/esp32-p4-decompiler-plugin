/* test_segment_tree_beats.c
 * Purpose   : Validate Segment Tree Beats (Ji Driver Segmentation)
 * Algorithm : The Segment Tree Beats (also known as "势能线段树" / Ji Driver
 *             Segmentation) supports the operation "chmin(l,r,v)" — set each
 *             element in [l,r] to min(a[i], v) — in amortised O(n log^2 n).
 *             Each node stores: max1 (largest value), max2 (second-largest),
 *             maxcnt (count of max1), sum.  When v < max1 and v >= max2, only
 *             the max elements are updated (the "break condition" kicks in).
 *
 * Array     : a = {5, 3, 7, 2, 8, 4, 6, 1} (N=8, 1-indexed internally)
 * Operations:
 *   chmin(1,8,6)  → {5,3,6,2,6,4,6,1}
 *   chmin(2,5,4)  → {5,3,4,2,4,4,6,1}
 *   query sum(1,8)  = 5+3+4+2+4+4+6+1 = 29
 *   query max(1,8)  = 6
 *   query sum(1,4)  = 5+3+4+2 = 14
 *
 * Expected  : n=8, total_sum=29, range_max=6  (14 & 0xFF won't fit cleanly;
 *             use 14 for sub-metric)
 * g_result  = (n<<16) | (total_sum<<8) | range_max
 *           = (8<<16) | (29<<8) | 6 = 0x081D06
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define STB_N    8
#define STB_MAXN (STB_N * 4)

static int stb_max1[STB_MAXN];   /* largest value in segment */
static int stb_max2[STB_MAXN];   /* second largest (strict) */
static int stb_maxcnt[STB_MAXN]; /* count of max1 */
static int stb_sum[STB_MAXN];
static int stb_lazy[STB_MAXN];   /* pending chmin value */

static const int stb_a[STB_N] = {5, 3, 7, 2, 8, 4, 6, 1};

static void stb_pushup(int nd) {
    stb_sum[nd] = stb_sum[nd*2] + stb_sum[nd*2+1];
    if (stb_max1[nd*2] == stb_max1[nd*2+1]) {
        stb_max1[nd]   = stb_max1[nd*2];
        stb_maxcnt[nd] = stb_maxcnt[nd*2] + stb_maxcnt[nd*2+1];
        int a = stb_max2[nd*2], b = stb_max2[nd*2+1];
        stb_max2[nd] = a > b ? a : b;
    } else if (stb_max1[nd*2] > stb_max1[nd*2+1]) {
        stb_max1[nd]   = stb_max1[nd*2];
        stb_maxcnt[nd] = stb_maxcnt[nd*2];
        int a = stb_max2[nd*2], b = stb_max1[nd*2+1];
        stb_max2[nd] = a > b ? a : b;
    } else {
        stb_max1[nd]   = stb_max1[nd*2+1];
        stb_maxcnt[nd] = stb_maxcnt[nd*2+1];
        int a = stb_max1[nd*2], b = stb_max2[nd*2+1];
        stb_max2[nd] = a > b ? a : b;
    }
}

static void stb_push_chmin(int nd, int val) {
    if (val >= stb_max1[nd]) return;
    stb_sum[nd]  -= (stb_max1[nd] - val) * stb_maxcnt[nd];
    stb_max1[nd]  = val;
    stb_lazy[nd]  = val;
}

static void stb_pushdown(int nd) {
    if (stb_lazy[nd] < 0x7FFFFFFF) {
        stb_push_chmin(nd*2,   stb_lazy[nd]);
        stb_push_chmin(nd*2+1, stb_lazy[nd]);
        stb_lazy[nd] = 0x7FFFFFFF;
    }
}

static void stb_build(int nd, int l, int r) {
    stb_lazy[nd] = 0x7FFFFFFF;
    if (l == r) {
        stb_sum[nd] = stb_max1[nd] = stb_a[l-1];
        stb_max2[nd] = -1;
        stb_maxcnt[nd] = 1;
        return;
    }
    int mid = (l + r) / 2;
    stb_build(nd*2, l, mid);
    stb_build(nd*2+1, mid+1, r);
    stb_pushup(nd);
}

static void stb_update(int nd, int l, int r, int ql, int qr, int val) {
    if (ql > r || qr < l || stb_max1[nd] <= val) return;
    if (ql <= l && r <= qr && stb_max2[nd] < val) {
        stb_push_chmin(nd, val);
        return;
    }
    stb_pushdown(nd);
    int mid = (l + r) / 2;
    stb_update(nd*2, l, mid, ql, qr, val);
    stb_update(nd*2+1, mid+1, r, ql, qr, val);
    stb_pushup(nd);
}

static int stb_query_sum(int nd, int l, int r, int ql, int qr) {
    if (ql > r || qr < l) return 0;
    if (ql <= l && r <= qr) return stb_sum[nd];
    stb_pushdown(nd);
    int mid = (l + r) / 2;
    return stb_query_sum(nd*2, l, mid, ql, qr) +
           stb_query_sum(nd*2+1, mid+1, r, ql, qr);
}

static int stb_query_max(int nd, int l, int r, int ql, int qr) {
    if (ql > r || qr < l) return -1;
    if (ql <= l && r <= qr) return stb_max1[nd];
    stb_pushdown(nd);
    int mid = (l + r) / 2;
    int a = stb_query_max(nd*2, l, mid, ql, qr);
    int b = stb_query_max(nd*2+1, mid+1, r, ql, qr);
    return a > b ? a : b;
}

void _start(void) {
    stb_build(1, 1, STB_N);

    stb_update(1, 1, STB_N, 1, STB_N, 6);  /* chmin(1..8, 6) */
    stb_update(1, 1, STB_N, 2, 5,     4);  /* chmin(2..5, 4) */

    int total_sum = stb_query_sum(1, 1, STB_N, 1, STB_N);
    int range_max = stb_query_max(1, 1, STB_N, 1, STB_N);

    g_result = ((uint32_t)STB_N << 16) |
               ((uint32_t)(total_sum & 0xFF) << 8) |
               (uint32_t)(range_max & 0xFF);
    while (1) {}
}
