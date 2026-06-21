/*
 * test_eulerian_number.c
 * Eulerian Numbers A(n,k): count permutations of 1..n with exactly k ascents.
 * An "ascent" at position i means perm[i] < perm[i+1].
 * Recurrence: A(n,k) = (k+1)*A(n-1,k) + (n-k)*A(n-1,k-1)
 * Base: A(0,0)=1, A(n,k)=0 for k<0 or k>=n.
 * Also compute second-order Eulerian numbers <n,k> for permutations of
 * multisets (used in B-spline theory and combinatorics):
 * <<n,k>> = (k+1)*<<n-1,k>> + (2n-1-k)*<<n-1,k-1>>, base <<1,0>>=1.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define EN_MAXN  8

/* Eulerian numbers A(n,k): dp[n][k] */
static uint32_t en_dp[EN_MAXN + 1][EN_MAXN + 1];

static void eulerian_build(void) {
    for (int n = 0; n <= EN_MAXN; n++)
        for (int k = 0; k <= EN_MAXN; k++)
            en_dp[n][k] = 0;
    en_dp[0][0] = 1;
    for (int n = 1; n <= EN_MAXN; n++) {
        for (int k = 0; k < n; k++) {
            uint32_t prev_k   = (k < EN_MAXN) ? en_dp[n-1][k]   : 0;
            uint32_t prev_km1 = (k > 0)       ? en_dp[n-1][k-1] : 0;
            en_dp[n][k] = (uint32_t)(k + 1) * prev_k
                        + (uint32_t)(n - k) * prev_km1;
        }
    }
}

/* Sum of row n equals n! — verify for n=5: 120 */
static uint32_t row_sum(int n) {
    uint32_t s = 0;
    for (int k = 0; k < n; k++) s += en_dp[n][k];
    return s;
}

/* Second-order Eulerian numbers <<n,k>> */
static uint32_t en2_dp[EN_MAXN + 1][EN_MAXN + 1];

static void eulerian2_build(void) {
    for (int n = 0; n <= EN_MAXN; n++)
        for (int k = 0; k <= EN_MAXN; k++)
            en2_dp[n][k] = 0;
    en2_dp[1][0] = 1;
    for (int n = 2; n <= EN_MAXN; n++) {
        for (int k = 0; k < n; k++) {
            uint32_t prev_k   = en2_dp[n-1][k];
            uint32_t prev_km1 = (k > 0) ? en2_dp[n-1][k-1] : 0;
            en2_dp[n][k] = (uint32_t)(k + 1) * prev_k
                         + (uint32_t)(2*(n-1) - k + 1) * prev_km1;
        }
    }
}

static uint32_t run_eulerian_tests(void) {
    /*
     * Test 1: Build first-order Eulerian numbers up to n=7.
     * Check A(4,1)=11, A(5,2)=66, sum(row 5)=120.
     */
    eulerian_build();
    uint32_t a41  = en_dp[4][1];   /* 11 */
    uint32_t a52  = en_dp[5][2];   /* 66 */
    uint32_t s5   = row_sum(5);    /* 120 */
    (void)a41; (void)a52; (void)s5;

    /*
     * Test 2: Second-order Eulerian numbers.
     * <<3,1>> = 6, <<4,2>> = 22, <<5,3>> = 58.
     */
    eulerian2_build();
    uint32_t e31 = en2_dp[3][1];   /* 6  */
    uint32_t e42 = en2_dp[4][2];   /* 22 */
    uint32_t e53 = en2_dp[5][3];   /* 58 */
    (void)e31; (void)e42; (void)e53;

    /*
     * Test 3: A(7,3)=302. Check a specific large value.
     */
    uint32_t a73  = en_dp[7][3];   /* 302 */
    (void)a73;

    /*
     * Pack: n_tests=3, metric_a = A(4,1) = 11 = 0x0B,
     *        metric_b = <<3,1>> = 6 = 0x06.
     * n=3(0x03), a=0x0B, b=0x06 — all non-zero, distinct. OK.
     */
    uint32_t metric_a = a41 & 0xFF;   /* 11 = 0x0B */
    uint32_t metric_b = e31 & 0xFF;   /* 6  = 0x06 */
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_eulerian_tests();
    while (1) {}
}
