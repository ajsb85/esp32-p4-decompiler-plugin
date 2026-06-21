/* test_wavelet_tree.c
 * Static wavelet tree for range frequency queries on an array of
 * values in [0, ALPHA) where ALPHA=8.
 * Supports: count occurrences of value v in A[l..r].
 *
 * g_result = (n_tests<<16) | (metric_a<<8) | metric_b
 *   n_tests  = 6   (query groups)
 *   metric_a = correct frequency queries out of 5 (expect 5)
 *   metric_b = correct range-rank queries out of 4 (expect 4)
 * => (6<<16)|(5<<8)|4 = 0x060504
 */
extern volatile unsigned g_result;

typedef unsigned int  uint;

#define N      16   /* array length */
#define ALPHA   8   /* value range [0, ALPHA) — must be power of 2 */
#define LEVELS  3   /* log2(ALPHA) */

/* Wavelet tree stored as level bitmaps.
 * At each level we have a bit for each position: 0=go-left, 1=go-right.
 * We also store prefix counts of zeros per level for range queries. */

static uint wt_bmap[LEVELS][N];   /* bmap[lv][i] = bit (0 or 1) */
static uint wt_cnt0[LEVELS][N+1]; /* cnt0[lv][i] = # zeros in bmap[lv][0..i-1] */

static uint arr[N];   /* original array */
static uint tmp[N];   /* scratch for building */

static void wt_build(void) {
    /* Copy arr into tmp as the "current sequence" */
    for (int i = 0; i < N; i++) tmp[i] = arr[i];

    for (int lv = LEVELS - 1; lv >= 0; lv--) {
        uint bit = 1u << lv;      /* the bit we're separating on */
        /* For each element: bit in value at this level */
        for (int i = 0; i < N; i++) {
            wt_bmap[lv][i] = (tmp[i] & bit) ? 1 : 0;
        }
        /* Build prefix count of zeros */
        wt_cnt0[lv][0] = 0;
        for (int i = 0; i < N; i++) {
            wt_cnt0[lv][i+1] = wt_cnt0[lv][i] + (wt_bmap[lv][i] == 0 ? 1 : 0);
        }
        /* Stable partition: zeros first, then ones, into tmp */
        static uint tmp2[N];
        int zi = 0, oi = (int)wt_cnt0[lv][N];
        for (int i = 0; i < N; i++) {
            if (wt_bmap[lv][i] == 0) tmp2[zi++] = tmp[i];
            else                      tmp2[oi++] = tmp[i];
        }
        for (int i = 0; i < N; i++) tmp[i] = tmp2[i];
    }
}

/* Count occurrences of value v in arr[l..r] (inclusive) */
static int wt_freq(int l, int r, uint v) {
    int lo = l, hi = r + 1; /* half-open [lo, hi) */
    for (int lv = LEVELS - 1; lv >= 0; lv--) {
        uint bit = 1u << lv;
        int zeros_total = (int)wt_cnt0[lv][N];
        if (v & bit) {
            /* go right: map positions to right partition */
            int nlo = zeros_total + (lo - (int)wt_cnt0[lv][lo]);
            int nhi = zeros_total + (hi - (int)wt_cnt0[lv][hi]);
            lo = nlo; hi = nhi;
        } else {
            /* go left: count zeros */
            lo = (int)wt_cnt0[lv][lo];
            hi = (int)wt_cnt0[lv][hi];
        }
    }
    return hi - lo;
}

/* count elements <= v in arr[l..r] */
static int wt_rank_leq(int l, int r, uint v) {
    int count = 0;
    for (uint val = 0; val <= v; val++) {
        count += wt_freq(l, r, val);
    }
    return count;
}

static int test_freq_queries(void) {
    /* arr = {3,1,4,1,5,9,2,6, 5,3,5,8->(7),9->(7),7,9->(7),3}
       clamp values to [0,8): use mod 8 */
    uint data[N] = {3,1,4,1,5,1,2,6, 5,3,5,7,7,7,7,3};
    for (int i = 0; i < N; i++) arr[i] = data[i];
    wt_build();

    int ok = 0;
    /* count 1s in [0,7]: 1,1,1 => 3 */
    if (wt_freq(0, 7, 1) == 3) ok++;
    /* count 3s in [0,15]: positions 0,9,15 => 3 */
    if (wt_freq(0, 15, 3) == 3) ok++;
    /* count 5s in [4,10]: positions 4,8,10 => 3 */
    if (wt_freq(4, 10, 5) == 3) ok++;
    /* count 7s in [11,14]: positions 11,12,13,14 => 4 */
    if (wt_freq(11, 14, 7) == 4) ok++;
    /* count 2s in [0,15]: position 6 => 1 */
    if (wt_freq(0, 15, 2) == 1) ok++;
    return ok; /* expect 5 */
}

static int test_rank_queries(void) {
    /* arr already built from test_freq_queries */
    int ok = 0;
    /* elements <= 1 in [0,3]: {3,1,1,1}->1,1 => 2 */
    if (wt_rank_leq(0, 3, 1) == 2) ok++;
    /* elements <= 5 in [0,7]: {3,1,4,1,5,1,2,6}: 1,4,1,5,1,2 => 6 */
    if (wt_rank_leq(0, 7, 5) == 6) ok++;
    /* elements <= 3 in [0,15]: 1,1,2,3,3,3 => 6 */
    if (wt_rank_leq(0, 15, 3) == 6) ok++;
    /* elements <= 7 in [11,14]: all 4 are 7 => 4 */
    if (wt_rank_leq(11, 14, 7) == 4) ok++;
    return ok; /* expect 4 */
}

void _start(void) {
    int t1 = test_freq_queries();  /* expect 5 */
    int t2 = test_rank_queries();  /* expect 4 */

    unsigned n_tests  = 6;
    unsigned metric_a = (unsigned)(t1 & 0xFF); /* 5 */
    unsigned metric_b = (unsigned)(t2 & 0xFF); /* 4 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    /* expected: 0x060504 */
}
