/*
 * test_segment_add_chmin.c
 * Segment tree beats ("Ji Driver Segment Tree"): supports two lazy operations:
 *   1. Range add: add v to all elements in [l,r]
 *   2. Range chmin: set each element a[i] = min(a[i], v) for i in [l,r]
 * Query: range max, range sum.
 *
 * Each node stores max1 (maximum), max2 (second maximum), cnt_max (count
 * of maximums), sum, lazy_add, lazy_chmin, size.
 * chmin only propagates when max1 > v > max2; breaks if max1 <= v,
 * descends if max2 >= v.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SAC_MAXN  32
#define SAC_INF   0x7FFFFFFF

typedef struct {
    int32_t max1, max2, cnt_max, sum, lazy_add, lazy_chmin, size;
} SACNode;

static SACNode st[SAC_MAXN * 4];
static int sac_sz;

static void sac_build(int nd, int l, int r, int32_t *a) {
    st[nd].lazy_add   = 0;
    st[nd].lazy_chmin = SAC_INF;
    st[nd].size       = r - l + 1;
    if (l == r) {
        st[nd].max1    = a[l];
        st[nd].max2    = -SAC_INF;
        st[nd].cnt_max = 1;
        st[nd].sum     = a[l];
        return;
    }
    int m = (l + r) / 2;
    sac_build(2*nd, l, m, a);
    sac_build(2*nd+1, m+1, r, a);
    /* pull up */
    st[nd].sum = st[2*nd].sum + st[2*nd+1].sum;
    if (st[2*nd].max1 > st[2*nd+1].max1) {
        st[nd].max1    = st[2*nd].max1;
        st[nd].cnt_max = st[2*nd].cnt_max;
        int32_t cand   = (st[2*nd].max2 > st[2*nd+1].max1)
                         ? st[2*nd].max2 : st[2*nd+1].max1;
        st[nd].max2    = cand;
    } else if (st[2*nd].max1 < st[2*nd+1].max1) {
        st[nd].max1    = st[2*nd+1].max1;
        st[nd].cnt_max = st[2*nd+1].cnt_max;
        int32_t cand   = (st[2*nd+1].max2 > st[2*nd].max1)
                         ? st[2*nd+1].max2 : st[2*nd].max1;
        st[nd].max2    = cand;
    } else {
        st[nd].max1    = st[2*nd].max1;
        st[nd].cnt_max = st[2*nd].cnt_max + st[2*nd+1].cnt_max;
        int32_t cand   = (st[2*nd].max2 > st[2*nd+1].max2)
                         ? st[2*nd].max2 : st[2*nd+1].max2;
        st[nd].max2    = cand;
    }
}

static void sac_push_add(int nd, int32_t v) {
    st[nd].max1     += v;
    if (st[nd].max2 != -SAC_INF) st[nd].max2 += v;
    if (st[nd].lazy_chmin != SAC_INF) st[nd].lazy_chmin += v;
    st[nd].sum      += v * st[nd].size;
    st[nd].lazy_add += v;
}

static void sac_push_chmin(int nd, int32_t v) {
    if (v >= st[nd].max1) return;
    st[nd].sum       -= (st[nd].max1 - v) * st[nd].cnt_max;
    st[nd].max1       = v;
    st[nd].lazy_chmin = v;
}

static void sac_pushdown(int nd) {
    if (st[nd].lazy_add != 0) {
        sac_push_add(2*nd,   st[nd].lazy_add);
        sac_push_add(2*nd+1, st[nd].lazy_add);
        st[nd].lazy_add = 0;
    }
    if (st[nd].lazy_chmin != SAC_INF) {
        sac_push_chmin(2*nd,   st[nd].lazy_chmin);
        sac_push_chmin(2*nd+1, st[nd].lazy_chmin);
        st[nd].lazy_chmin = SAC_INF;
    }
}

static void sac_pullup(int nd) {
    st[nd].sum = st[2*nd].sum + st[2*nd+1].sum;
    if (st[2*nd].max1 > st[2*nd+1].max1) {
        st[nd].max1    = st[2*nd].max1;
        st[nd].cnt_max = st[2*nd].cnt_max;
        int32_t cand   = (st[2*nd].max2 > st[2*nd+1].max1)
                         ? st[2*nd].max2 : st[2*nd+1].max1;
        st[nd].max2    = cand;
    } else if (st[2*nd].max1 < st[2*nd+1].max1) {
        st[nd].max1    = st[2*nd+1].max1;
        st[nd].cnt_max = st[2*nd+1].cnt_max;
        int32_t cand   = (st[2*nd+1].max2 > st[2*nd].max1)
                         ? st[2*nd+1].max2 : st[2*nd].max1;
        st[nd].max2    = cand;
    } else {
        st[nd].max1    = st[2*nd].max1;
        st[nd].cnt_max = st[2*nd].cnt_max + st[2*nd+1].cnt_max;
        int32_t cand   = (st[2*nd].max2 > st[2*nd+1].max2)
                         ? st[2*nd].max2 : st[2*nd+1].max2;
        st[nd].max2    = cand;
    }
}

static void sac_range_add(int nd, int l, int r, int ql, int qr, int32_t v) {
    if (ql > r || qr < l) return;
    if (ql <= l && r <= qr) { sac_push_add(nd, v); return; }
    sac_pushdown(nd);
    int m = (l + r) / 2;
    sac_range_add(2*nd,   l, m,   ql, qr, v);
    sac_range_add(2*nd+1, m+1, r, ql, qr, v);
    sac_pullup(nd);
}

static void sac_range_chmin(int nd, int l, int r, int ql, int qr, int32_t v) {
    if (ql > r || qr < l || v >= st[nd].max1) return;
    if (ql <= l && r <= qr && v > st[nd].max2) {
        sac_push_chmin(nd, v);
        return;
    }
    sac_pushdown(nd);
    int m = (l + r) / 2;
    sac_range_chmin(2*nd,   l, m,   ql, qr, v);
    sac_range_chmin(2*nd+1, m+1, r, ql, qr, v);
    sac_pullup(nd);
}

static int32_t sac_query_max(int nd, int l, int r, int ql, int qr) {
    if (ql > r || qr < l) return -SAC_INF;
    if (ql <= l && r <= qr) return st[nd].max1;
    sac_pushdown(nd);
    int m = (l + r) / 2;
    int32_t lv = sac_query_max(2*nd,   l, m,   ql, qr);
    int32_t rv = sac_query_max(2*nd+1, m+1, r, ql, qr);
    return lv > rv ? lv : rv;
}

static int32_t sac_query_sum(int nd, int l, int r, int ql, int qr) {
    if (ql > r || qr < l) return 0;
    if (ql <= l && r <= qr) return st[nd].sum;
    sac_pushdown(nd);
    int m = (l + r) / 2;
    return sac_query_sum(2*nd, l, m, ql, qr)
         + sac_query_sum(2*nd+1, m+1, r, ql, qr);
}

static uint32_t run_sac_tests(void) {
    sac_sz = 8;
    /*
     * Array (1-indexed): [3, 1, 4, 1, 5, 9, 2, 6]
     */
    int32_t a[9] = {0, 3, 1, 4, 1, 5, 9, 2, 6};
    sac_build(1, 1, sac_sz, a + 1);

    /*
     * Test 1: range_add [2,5] += 3 -> [3, 4, 7, 4, 8, 9, 2, 6]
     * Query max [1,8] = 9  (unused, for completeness).
     */
    sac_range_add(1, 1, sac_sz, 2, 5, 3);
    int32_t max1 = sac_query_max(1, 1, sac_sz, 1, sac_sz); /* expect 9 */
    (void)max1;

    /*
     * Test 2: range_chmin [1,8] with 7 -> [3, 4, 7, 4, 7, 7, 2, 6]
     * Query max [1,8] = 7.
     */
    sac_range_chmin(1, 1, sac_sz, 1, sac_sz, 7);
    int32_t max2 = sac_query_max(1, 1, sac_sz, 1, sac_sz); /* expect 7 */

    /*
     * Test 3: query sum [3,6] = 7+4+7+7 = 25.
     */
    int32_t sum3 = sac_query_sum(1, 1, sac_sz, 3, 6); /* expect 25 */

    /*
     * Pack: n_tests=3, metric_a=max2=7=0x07, metric_b=sum3=25=0x19
     * result = (3<<16)|(0x07<<8)|0x19 = 0x030719
     * Bytes: 0x03, 0x07, 0x19 all non-zero and distinct.
     */
    uint32_t metric_a = (uint32_t)(max2 & 0x7F); /* 7  = 0x07 */
    uint32_t metric_b = (uint32_t)(sum3 & 0xFF); /* 25 = 0x19 */
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_sac_tests();
    while (1) {}
}
