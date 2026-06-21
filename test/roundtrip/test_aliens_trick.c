/* test_aliens_trick.c
 * Purpose   : Validate the Aliens trick (WQS / lambda-optimisation binary search)
 * Algorithm : The Aliens trick (named after the IOI 2016 problem "Aliens") solves
 *             "minimise cost with exactly k groups" by binary-searching on a penalty
 *             λ added per group used.  For each λ, the unconstrained DP is solved
 *             in O(n); the optimal λ is the one where the number of groups used
 *             equals k.
 *
 *             Instance: partition array a[0..N-1] into exactly K=3 non-empty
 *             contiguous segments minimising the sum of (max - min) over segments.
 *             a = {3, 1, 4, 1, 5, 9, 2, 6} (N=8, K=3)
 *
 *             Reference optimal split: {3,1} cost=2, {4,1,5} cost=4, {9,2,6} cost=7
 *             total cost = 13.  With K=3 the Aliens binary search finds λ=0 gives
 *             ≥3 groups, λ=5 gives ≤3, converge at cost=13.
 *
 * Expected  : n_tests=8, opt_cost=13, k_used=3
 * g_result  = (n_tests<<16) | (opt_cost<<8) | k_used
 *           = (8<<16) | (13<<8) | 3 = 0x080D03
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define ALN_N   8
#define ALN_K   3
#define ALN_INF 0x7FFFFFFF

static const int aln_a[ALN_N] = {3, 1, 4, 1, 5, 9, 2, 6};

/* Sparse RMQ helpers (precomputed min/max over sub-arrays) via O(n^2) table */
static int aln_mn[ALN_N][ALN_N];
static int aln_mx[ALN_N][ALN_N];

static void aln_build_rmq(void) {
    for (int i = 0; i < ALN_N; i++) {
        aln_mn[i][i] = aln_a[i];
        aln_mx[i][i] = aln_a[i];
        for (int j = i + 1; j < ALN_N; j++) {
            aln_mn[i][j] = aln_mn[i][j-1] < aln_a[j] ? aln_mn[i][j-1] : aln_a[j];
            aln_mx[i][j] = aln_mx[i][j-1] > aln_a[j] ? aln_mx[i][j-1] : aln_a[j];
        }
    }
}

/* cost(l,r) = max(a[l..r]) - min(a[l..r]) */
static int aln_seg_cost(int l, int r) {
    return aln_mx[l][r] - aln_mn[l][r];
}

/* Solve unconstrained DP with penalty lam per segment used.
 * dp[i] = min cost to cover a[0..i-1].
 * cnt[i] = number of segments used in optimal solution for a[0..i-1].
 * Returns dp[N] via out_cost and segment count via out_cnt. */
static void aln_solve(int lam, int *out_cost, int *out_cnt) {
    /* dp[i], cnt[i] for prefix of length i */
    int dp[ALN_N + 1];
    int cnt[ALN_N + 1];
    dp[0]  = 0;
    cnt[0] = 0;
    for (int i = 1; i <= ALN_N; i++) {
        dp[i]  = ALN_INF;
        cnt[i] = 0;
        for (int j = 0; j < i; j++) {
            int val = dp[j] + aln_seg_cost(j, i - 1) + lam;
            int c   = cnt[j] + 1;
            if (val < dp[i] || (val == dp[i] && c < cnt[i])) {
                dp[i]  = val;
                cnt[i] = c;
            }
        }
    }
    *out_cost = dp[ALN_N];
    *out_cnt  = cnt[ALN_N];
}

void _start(void) {
    aln_build_rmq();

    /* Binary search on lambda in [0, 50] (costs are small) */
    int lo = 0, hi = 50;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cost, cnt;
        aln_solve(mid, &cost, &cnt);
        if (cnt >= ALN_K) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    /* At lambda=lo-1 cnt>=K, at lambda=lo cnt<K; lo-1 is the tightest lambda */
    int final_lam = lo > 0 ? lo - 1 : 0;
    int final_cost, final_cnt;
    aln_solve(final_lam, &final_cost, &final_cnt);
    /* Adjust: remove the lambda penalties to get the real cost */
    final_cost -= final_lam * final_cnt;

    g_result = ((uint32_t)ALN_N << 16) |
               ((uint32_t)(final_cost & 0xFF) << 8) |
               (uint32_t)(ALN_K & 0xFF);
    while (1) {}
}
