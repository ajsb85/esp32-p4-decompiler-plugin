/* test_weighted_interval_scheduling.c
 * Purpose   : Weighted interval scheduling — maximize total weight of
 *             non-overlapping intervals, solved with DP + binary search.
 * Algorithm : Sort intervals by finish time. For each interval i, find
 *             p(i) = last interval j that finishes before i starts (binary
 *             search on finish times). dp[i] = max(dp[i-1],
 *             weight[i] + dp[p(i)]).
 * Intervals : {start,finish,weight}
 *   0: {1,3,3}, 1: {2,5,4}, 2: {4,6,5}, 3: {6,8,7},
 *   4: {5,7,2}, 5: {7,9,6}
 * Sorted by finish: (1,3,3),(2,5,4),(4,6,5),(5,7,2),(6,8,7),(7,9,6)
 * pred[]: p[0]=-1, p[1]=-1, p[2]=0, p[3]=1, p[4]=2, p[5]=3
 * dp[0..7]: 0,3,4,8,8,15,15
 *   dp[5]=max(dp[4]=8, w[4]+dp[p[4]+1]=7+8=15)=15
 *   dp[6]=max(dp[5]=15, w[5]+dp[p[5]+1]=6+8=14)=15
 * best_weight=15, n_intervals=6, n_selected=2 (backtrack result)
 * g_result = (n_intervals << 16) | (best_weight << 8) | n_selected
 *          = (6 << 16) | (15 << 8) | 2 = 0x060F02
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define WIS_N 6

typedef struct {
    int start;
    int finish;
    int weight;
} WisInterval;

static WisInterval wis_ivs[WIS_N] = {
    {1,3,3}, {2,5,4}, {4,6,5}, {6,8,7}, {5,7,2}, {7,9,6}
};

static int wis_dp[WIS_N + 1];  /* dp[0]=0, dp[i]=best using first i intervals */

/* Sort by finish time (insertion sort) */
static void wis_sort(void) {
    for (int i = 1; i < WIS_N; i++) {
        WisInterval key = wis_ivs[i];
        int j = i - 1;
        while (j >= 0 && wis_ivs[j].finish > key.finish) {
            wis_ivs[j+1] = wis_ivs[j];
            j--;
        }
        wis_ivs[j+1] = key;
    }
}

/* Binary search: last interval with finish <= t, returns index (-1 if none) */
static int wis_pred(int i) {
    int t = wis_ivs[i].start;
    int lo = 0, hi = i - 1, ans = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (wis_ivs[mid].finish <= t) {
            ans = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return ans;
}

/* Backtrack to count selected intervals */
static int wis_count_selected(void) {
    int cnt = 0;
    int i = WIS_N - 1;
    while (i >= 0) {
        int p = wis_pred(i);
        int dp_p = (p >= 0) ? wis_dp[p + 1] : 0;
        if (wis_ivs[i].weight + dp_p > wis_dp[i]) {
            /* came from dp[i] = dp[i-1], skip this interval */
            i--;
        } else {
            cnt++;
            i = p;
        }
    }
    return cnt;
}

static void wis_solve(void) {
    wis_sort();
    wis_dp[0] = 0;
    for (int i = 0; i < WIS_N; i++) {
        int p = wis_pred(i);
        int dp_p = (p >= 0) ? wis_dp[p + 1] : 0;
        int take = wis_ivs[i].weight + dp_p;
        int skip = wis_dp[i];
        wis_dp[i + 1] = (take > skip) ? take : skip;
    }
}

void _start(void) {
    wis_solve();

    int best_weight = wis_dp[WIS_N];
    int n_selected  = wis_count_selected();

    g_result = ((uint32_t)WIS_N       << 16)
             | ((uint32_t)best_weight  << 8)
             | ((uint32_t)n_selected);
    while (1) {}
}
