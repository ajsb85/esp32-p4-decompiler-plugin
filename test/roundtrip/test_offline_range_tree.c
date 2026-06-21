/*
 * test_offline_range_tree.c
 * Offline 2D range tree / fractional-cascading simulation:
 * Given a set of 2D points, answer offline range-count queries
 * [x1..x2] x [y1..y2] using a merge-sort tree (each node of a
 * segment tree on x stores the sorted list of y-values in its range),
 * enabling O(log^2 n) per query via binary search.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define ORT_MAXN   8     /* max points */
#define ORT_MAXSEG (ORT_MAXN * 4)
#define ORT_BUFSZ  (ORT_MAXN * 20) /* storage for all sorted sub-lists */

typedef struct { int x, y; } OrtPt;

static OrtPt ort_pts[ORT_MAXN];
static int   ort_n;

/* Each seg-tree node: sorted y-list stored in ort_buf at offset ort_off[node] */
static int ort_buf[ORT_BUFSZ];
static int ort_off[ORT_MAXSEG]; /* start offset in ort_buf */
static int ort_len[ORT_MAXSEG]; /* length of sorted list */
static int ort_bufpos;

/* Temporary merge buffer */
static int ort_tmp[ORT_MAXN];

static void ort_merge(int *a, int la, int *b, int lb, int *out) {
    int i = 0, j = 0, k = 0;
    while (i < la && j < lb) out[k++] = (a[i] <= b[j]) ? a[i++] : b[j++];
    while (i < la) out[k++] = a[i++];
    while (j < lb) out[k++] = b[j++];
}

/* Count elements in sorted array a[0..n-1] that lie in [lo..hi] */
static int ort_count_range(const int *a, int n, int lo, int hi) {
    /* lower_bound(lo) */
    int lb = 0, ub = n;
    while (lb < ub) { int m = (lb+ub)/2; if (a[m] < lo) lb=m+1; else ub=m; }
    int left = lb;
    lb = 0; ub = n;
    while (lb < ub) { int m = (lb+ub)/2; if (a[m] <= hi) lb=m+1; else ub=m; }
    return lb - left;
}

/* Build merge-sort tree on x-coordinates [root=1, covers pts sorted by x] */
static void ort_build(int node, int l, int r) {
    ort_off[node] = ort_bufpos;
    ort_len[node] = r - l + 1;
    /* Copy y-values of pts[l..r] sorted (pts already sorted by x for leaves,
       inner nodes merge children) */
    if (l == r) {
        ort_buf[ort_bufpos++] = ort_pts[l].y;
        return;
    }
    int mid = (l + r) / 2;
    ort_build(node*2,   l,   mid);
    ort_build(node*2+1, mid+1, r);
    /* Merge children's y-lists */
    ort_merge(ort_buf + ort_off[node*2],   ort_len[node*2],
              ort_buf + ort_off[node*2+1], ort_len[node*2+1],
              ort_tmp);
    for (int i = 0; i < ort_len[node]; i++)
        ort_buf[ort_bufpos++] = ort_tmp[i];
}

/* Query: count points with x in [xl..xr] and y in [yl..yr] */
static int ort_query(int node, int l, int r, int xl, int xr, int yl, int yr) {
    if (xl > r || xr < l) return 0;
    if (xl <= l && r <= xr)
        return ort_count_range(ort_buf + ort_off[node], ort_len[node], yl, yr);
    int mid = (l + r) / 2;
    return ort_query(node*2,   l,   mid, xl, xr, yl, yr)
         + ort_query(node*2+1, mid+1, r, xl, xr, yl, yr);
}

/* Sort pts by x (insertion sort) */
static void ort_sort_x(void) {
    for (int i = 1; i < ort_n; i++) {
        OrtPt key = ort_pts[i];
        int j = i - 1;
        while (j >= 0 && ort_pts[j].x > key.x) { ort_pts[j+1] = ort_pts[j]; j--; }
        ort_pts[j+1] = key;
    }
}

static uint32_t run_ort_tests(void) {
    /*
     * Test 1: 5 points, count in [2..4] x [2..4].
     * Points: (1,3),(2,1),(3,4),(4,2),(5,5)
     * After sort by x (already sorted): same.
     * Points with x in [2..4]: (2,1),(3,4),(4,2).
     * Of those with y in [2..4]: (3,4),(4,2) -> count=2.
     */
    ort_n = 5;
    ort_pts[0] = (OrtPt){1,3}; ort_pts[1] = (OrtPt){2,1};
    ort_pts[2] = (OrtPt){3,4}; ort_pts[3] = (OrtPt){4,2};
    ort_pts[4] = (OrtPt){5,5};
    ort_sort_x();
    ort_bufpos = 0;
    ort_build(1, 0, ort_n-1);
    int cnt1 = ort_query(1, 0, ort_n-1, 2, 4, 2, 4); /* expect 2 */

    /*
     * Test 2: All points in full range -> 5.
     */
    int cnt2 = ort_query(1, 0, ort_n-1, 1, 5, 1, 5); /* expect 5 */

    /*
     * Test 3: Empty range -> 0.
     */
    int cnt3 = ort_query(1, 0, ort_n-1, 6, 8, 1, 5); /* expect 0 */
    int ok3 = (cnt3 == 0);
    (void)ok3;

    /*
     * Pack: n_tests=3, metric_a=cnt1=2=0x02, metric_b=cnt2=5=0x05.
     * Bytes: 0x03, 0x02, 0x05 — all non-zero, but 0x03 and 0x02 too close.
     * Use metric_a = cnt1*0x11=0x22, metric_b=cnt2*0x09=0x2D.
     * Bytes: 0x03, 0x22, 0x2D — non-zero, distinct.
     */
    uint32_t metric_a = (uint32_t)(cnt1 * 0x11u); /* 2*17=34=0x22 */
    uint32_t metric_b = (uint32_t)(cnt2 * 0x09u); /* 5*9=45=0x2D */
    return (3u << 16) | (metric_a << 8) | (metric_b & 0xFF);
}

void _start(void) {
    g_result = run_ort_tests();
    while (1) {}
}
