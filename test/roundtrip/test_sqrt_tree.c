/* test_sqrt_tree.c — sqrt-tree (O(1) RMQ with O(n log log n) build)
 * Self-contained, no system includes except <stdint.h>.
 * Compiles with:
 *   riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f \
 *     -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_sqrt_tree.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── integer log2 ────────────────────────────────────────────────────────── */
static uint32_t ilog2(uint32_t x) {
    uint32_t r = 0;
    while (x > 1) { x >>= 1; r++; }
    return r;
}

/* ── sqrt-tree for range-minimum query ───────────────────────────────────── */
#define SQTREE_N   64
#define SQTREE_B    8   /* block size = sqrt(N) */
#define SQTREE_NB   8   /* number of blocks     */

static int32_t sqt_arr[SQTREE_N];

/* prefix min within each block */
static int32_t sqt_pmin[SQTREE_N];
/* suffix min within each block */
static int32_t sqt_smin[SQTREE_N];
/* block minimum array (one entry per block) */
static int32_t sqt_bmin[SQTREE_NB];
/* sparse-table on block minimums: sparse[k][b] = min of 2^k blocks from b */
#define SQTREE_LOG  4
static int32_t sqt_sparse[SQTREE_LOG][SQTREE_NB];

static int32_t sqt_min(int32_t a, int32_t b) { return a < b ? a : b; }

static void sqt_build(void) {
    uint32_t i, b, k;
    /* prefix/suffix mins inside each block */
    for (b = 0; b < SQTREE_NB; b++) {
        uint32_t lo = b * SQTREE_B;
        uint32_t hi = lo + SQTREE_B;   /* exclusive */
        sqt_pmin[lo] = sqt_arr[lo];
        for (i = lo + 1; i < hi; i++)
            sqt_pmin[i] = sqt_min(sqt_pmin[i-1], sqt_arr[i]);
        sqt_smin[hi-1] = sqt_arr[hi-1];
        for (i = hi - 2; (int32_t)i >= (int32_t)lo; i--)
            sqt_smin[i] = sqt_min(sqt_smin[i+1], sqt_arr[i]);
        sqt_bmin[b] = sqt_pmin[hi-1];
    }
    /* sparse table on block mins */
    for (b = 0; b < SQTREE_NB; b++)
        sqt_sparse[0][b] = sqt_bmin[b];
    for (k = 1; k < SQTREE_LOG; k++) {
        uint32_t half = 1u << (k-1);
        for (b = 0; b + (1u << k) <= SQTREE_NB; b++)
            sqt_sparse[k][b] = sqt_min(sqt_sparse[k-1][b],
                                        sqt_sparse[k-1][b + half]);
    }
}

/* O(1) RMQ on [l, r] inclusive */
static int32_t sqt_query(uint32_t l, uint32_t r) {
    uint32_t bl = l / SQTREE_B, br = r / SQTREE_B;
    if (bl == br) {
        /* same block: linear scan (still O(B) = O(sqrt N)) */
        int32_t res = sqt_arr[l];
        uint32_t i;
        for (i = l+1; i <= r; i++)
            res = sqt_min(res, sqt_arr[i]);
        return res;
    }
    /* suffix of left block + block-level sparse + prefix of right block */
    int32_t res = sqt_min(sqt_smin[l], sqt_pmin[r]);
    uint32_t lb = bl + 1, rb = br - 1;
    if (lb <= rb) {
        uint32_t k = ilog2(rb - lb + 1);
        res = sqt_min(res, sqt_min(sqt_sparse[k][lb],
                                    sqt_sparse[k][rb - (1u<<k) + 1]));
    }
    return res;
}

/* ── test driver ─────────────────────────────────────────────────────────── */
static void run_sqrt_tree_test(void) {
    uint32_t i;
    /* fill array with a pattern: arr[i] = (i*7+3) % 53 */
    for (i = 0; i < SQTREE_N; i++)
        sqt_arr[i] = (int32_t)((i * 7u + 3u) % 53u);

    sqt_build();

    /* run a series of queries */
    uint32_t n_tests = 0;
    int32_t  chk_a   = 0, chk_b = 0;

    /* query #1: full range */
    int32_t q1 = sqt_query(0, SQTREE_N - 1);
    chk_a ^= (int32_t)(uint32_t)q1;
    n_tests++;

    /* query #2: single element */
    int32_t q2 = sqt_query(5, 5);
    chk_b ^= (int32_t)(uint32_t)q2;
    n_tests++;

    /* query #3: cross-block range */
    int32_t q3 = sqt_query(3, 20);
    chk_a ^= (int32_t)(uint32_t)q3;
    n_tests++;

    /* query #4: last block only */
    int32_t q4 = sqt_query(56, 63);
    chk_b ^= (int32_t)(uint32_t)q4;
    n_tests++;

    /* query #5: mid range */
    int32_t q5 = sqt_query(10, 50);
    chk_a += (int32_t)(uint32_t)q5;
    n_tests++;

    /* make metrics non-zero and distinct */
    uint32_t metric_a = ((uint32_t)chk_a & 0xFFu) | 0x01u;
    uint32_t metric_b = (((uint32_t)chk_b >> 4u) & 0xFFu) | 0x02u;
    if (metric_a == metric_b) metric_b ^= 0x10u;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    run_sqrt_tree_test();
    while (1) {}
}
