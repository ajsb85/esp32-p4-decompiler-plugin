/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Convex Hull Trick (CHT) DP optimisation fixture.
 *
 * The Convex Hull Trick accelerates DP transitions of the form
 *   dp[i] = min over j<i of { dp[j] + a[j]*b[i] + c[i] }
 * by maintaining a lower convex hull of lines y = m*x + q and querying
 * the minimum value in O(1) amortised when queries are monotone.
 *
 * Classic application: "slope trick" for 1D facility location / task scheduling.
 *
 * Test: minimize cost of dividing array into groups.
 *   Weights w[] = {1, 2, 3, 4, 5, 6, 7}  (n = 7)
 *   dp[i] = min cost to process first i elements.
 *   dp[0] = 0
 *   dp[i] = min_{0<=j<i} ( dp[j] + cost(j+1..i) )
 *   where cost(l..r) = sum(w[l..r])^2  (penalise large groups)
 *
 *   This reduces to dp[i] = dp[j] + (prefix[i]-prefix[j])^2
 *                         = dp[j] + prefix[i]^2 - 2*prefix[i]*prefix[j] + prefix[j]^2
 *   Line for j: slope m = -2*prefix[j], intercept q = dp[j] + prefix[j]^2
 *   Query at i:  y(m) at x = prefix[i], then add prefix[i]^2
 *
 * prefix[] = {0,1,3,6,10,15,21,28}
 * Manual dp:
 *   dp[0]=0
 *   dp[1]= dp[0]+(1)^2 =1
 *   dp[2]= min(dp[0]+(3)^2, dp[1]+(2)^2) = min(9,5)=5
 *   dp[3]= min(dp[0]+36, dp[1]+25, dp[2]+9) = min(36,26,14)=14
 *   dp[4]= min(dp[0]+100, dp[1]+81, dp[2]+49, dp[3]+16) = min(100,82,54,30)=30
 *   dp[5]= min(...,dp[4]+25) = min(225,196,149,100,55)=55
 *   dp[6]= min(...,dp[5]+36) = min(441,400,320,225,130,91)=91
 *   dp[7]= min(...,dp[6]+49) = min(784,729,595,441,280,175,140)=140
 *
 * Metrics:
 *   n_tests  = 7   (array length)
 *   metric_a = 140 & 0xFF = 0x8C   (dp[7] mod 256 = 140 = 0x8C)
 *   BUT 0x8C == 140 and n_tests=7 and we need all bytes non-zero and distinct
 *   (7 != 0, 0x8C=140 != 0, need metric_b != 0 and distinct from 7 and 140)
 *   metric_b = number of groups in the optimal partition = ?
 *   Backtrack: dp[7]=140 comes from dp[6]+49=140 → dp[6]=91
 *              dp[6]=91  comes from dp[5]+36=91  → dp[5]=55
 *              dp[5]=55  comes from dp[4]+25=55  → dp[4]=30
 *              dp[4]=30  comes from dp[3]+16=30  → dp[3]=14
 *              dp[3]=14  comes from dp[2]+9=14   → dp[2]=5
 *              dp[2]=5   comes from dp[1]+4=5    → dp[1]=1
 *              dp[1]=1   comes from dp[0]+1=1    → dp[0]=0
 *   Each element is its own group → 7 groups. That's the same as n_tests.
 *   Use metric_b = (dp[7] >> 4) & 0xFF = (140>>4)=8 — distinct from 7 and 140.
 *   Actually let's pick metric_b = count of dp values that are perfect squares:
 *   dp values: 0,1,5,14,30,55,91,140 → only dp[0]=0 and dp[1]=1 are perfect squares
 *   (0 not valid since it's 0). dp[1]=1 yes, rest no. metric_b=1 — too small.
 *   Better: use number of DP states where dp[i]-dp[i-1] increases: 1,4,9,16,25,36,49 all increase → 6 transitions.
 *   metric_b = 6 — distinct from 7 (n_tests) and 140 (metric_a). Non-zero. OK.
 *   But 0x0706 would be the upper bytes... let's check all 3 are distinct:
 *   n_tests=7=0x07, metric_a=140=0x8C, metric_b=6=0x06. 0x07 != 0x8C != 0x06 != 0x07.
 *   But 7 and 6 differ only by 1, but they are different bytes. OK.
 *   Actually wait — the requirement says all 3 bytes non-zero and distinct. 0x07, 0x8C, 0x06 are all non-zero and all different. Good.
 *
 * g_result = (7<<16)|(140<<8)|6 = 0x078C06
 */

#include <stdint.h>

volatile uint32_t g_result;

#define CHT_N 8   /* 7 elements + prefix[0]=0 */

/* CHT: lines y = m*x + q, minimise */
typedef struct {
    int64_t m;  /* slope */
    int64_t q;  /* intercept */
} Line;

static Line hull[CHT_N];
static int  hull_sz;

/* returns 1 if the middle line b is never the minimum (can be removed) */
static int cht_bad(Line a, Line b, Line c) {
    /* intersection of a,c is to the left of intersection of a,b */
    /* (c.q - a.q)*(a.m - b.m) <= (b.q - a.q)*(a.m - c.m) */
    return (int64_t)(c.q - a.q) * (a.m - b.m) <= (int64_t)(b.q - a.q) * (a.m - c.m);
}

static void cht_add(int64_t m, int64_t q) {
    Line nl = {m, q};
    while (hull_sz >= 2 && cht_bad(hull[hull_sz-2], hull[hull_sz-1], nl))
        hull_sz--;
    hull[hull_sz++] = nl;
}

/* query minimum y at x (monotone non-decreasing x, so pointer walks) */
static int ptr_idx;

static int64_t cht_query(int64_t x) {
    while (ptr_idx + 1 < hull_sz &&
           hull[ptr_idx+1].m * x + hull[ptr_idx+1].q <=
           hull[ptr_idx  ].m * x + hull[ptr_idx  ].q)
        ptr_idx++;
    return hull[ptr_idx].m * x + hull[ptr_idx].q;
}

void _start(void) {
    const int n = 7;
    const int64_t w[8] = {0, 1, 2, 3, 4, 5, 6, 7};  /* w[1..7] are the weights */

    /* build prefix sums */
    int64_t prefix[CHT_N];
    prefix[0] = 0;
    for (int i = 1; i <= n; i++) prefix[i] = prefix[i-1] + w[i];

    int64_t dp[CHT_N];
    dp[0] = 0;

    hull_sz  = 0;
    ptr_idx  = 0;

    /* add line for j=0: m = -2*prefix[0] = 0, q = dp[0]+prefix[0]^2 = 0 */
    cht_add(-2 * prefix[0], dp[0] + prefix[0] * prefix[0]);

    for (int i = 1; i <= n; i++) {
        dp[i] = cht_query(prefix[i]) + prefix[i] * prefix[i];
        /* add line for j=i: m = -2*prefix[i], q = dp[i]+prefix[i]^2 */
        cht_add(-2 * prefix[i], dp[i] + prefix[i] * prefix[i]);
    }
    /* dp[7] should be 140 */

    /* count transitions where dp[i] - dp[i-1] strictly increases */
    int inc = 0;
    for (int i = 2; i <= n; i++) {
        if ((dp[i] - dp[i-1]) > (dp[i-1] - dp[i-2])) inc++;
    }
    /* differences: 1,4,9,16,25,36,49 → each > previous → 6 increasing */

    uint32_t n_tests  = (uint32_t)n;                     /* 7    = 0x07 */
    uint32_t metric_a = (uint32_t)((int32_t)dp[n] & 0xFF); /* 140  = 0x8C */
    uint32_t metric_b = (uint32_t)(inc & 0xFF);           /* 6    = 0x06 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    /* expected: 0x078C06 */
    while (1) {}
}
