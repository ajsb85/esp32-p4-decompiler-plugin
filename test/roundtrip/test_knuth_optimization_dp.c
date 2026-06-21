/* test_knuth_optimization_dp.c
 * Knuth-Yao optimization for interval DP (optimal BST / stone-merge cost).
 * The optimization restricts opt[i][j-1] <= opt[i][j] <= opt[i+1][j], reducing
 * O(n^3) DP to O(n^2) when the cost satisfies the quadrangle inequality.
 * All arithmetic 32-bit only.
 */
#include <stdint.h>

#define KN_N 8

/* prefix sums of weights */
static uint32_t kn_w[KN_N + 1];   /* kn_w[i] = sum of weights[0..i-1] */
/* DP cost table and opt table */
static uint32_t kn_dp[KN_N][KN_N];
static uint32_t kn_opt[KN_N][KN_N];

volatile uint32_t g_result;

/* range sum of weights[l..r] (0-indexed, inclusive) */
static uint32_t kn_range_w(uint32_t l, uint32_t r) {
    return kn_w[r + 1] - kn_w[l];
}

static void knuth_opt_dp(void) {
    /* weights: 1..8 */
    kn_w[0] = 0;
    for (uint32_t i = 0; i < KN_N; i++) {
        kn_w[i + 1] = kn_w[i] + (i + 1);
    }

    /* init: single elements */
    for (uint32_t i = 0; i < KN_N; i++) {
        kn_dp[i][i] = 0;
        kn_opt[i][i] = i;
    }

    /* fill by increasing interval length */
    for (uint32_t len = 2; len <= KN_N; len++) {
        for (uint32_t i = 0; i + len - 1 < KN_N; i++) {
            uint32_t j = i + len - 1;
            uint32_t best_cost = 0xFFFFFFFFu;
            uint32_t best_k = kn_opt[i][j - 1];
            uint32_t khi = (j > 0) ? kn_opt[i + 1][j] : j;
            if (khi > j) khi = j;
            for (uint32_t k = best_k; k <= khi; k++) {
                uint32_t left  = (k > i) ? kn_dp[i][k - 1] : 0;
                uint32_t right = (k < j) ? kn_dp[k + 1][j] : 0;
                uint32_t cost  = left + right + kn_range_w(i, j);
                if (cost < best_cost) {
                    best_cost = cost;
                    kn_opt[i][j] = k;
                }
            }
            kn_dp[i][j] = best_cost;
        }
    }
}

void _start(void) {
    knuth_opt_dp();

    /* extract metrics */
    uint32_t total_cost = kn_dp[0][KN_N - 1];
    uint32_t root_k     = kn_opt[0][KN_N - 1];
    uint32_t mid_k      = kn_opt[1][KN_N - 2];

    /* pack: n_tests=3, metric_a=(cost&0x7f)|0x01, metric_b=(root_k<<4)|mid_k+1 */
    uint32_t n_tests  = 3;
    uint32_t metric_a = ((total_cost & 0x7Fu) | 0x01u);
    if (metric_a == 0) metric_a = 1;
    uint32_t metric_b = ((root_k << 4) | (mid_k + 1)) & 0xFFu;
    if (metric_b == 0) metric_b = 0x12u;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    while (1) {}
}
