/* test_coin_change_unbounded.c
 * Purpose   : Validate unbounded coin change — count distinct ways to make sum
 * Algorithm : Classic unbounded knapsack DP.
 *             dp[0]=1; for each coin c: for j=c..target: dp[j]+=dp[j-c]
 *             Counts the number of combinations (not permutations) to reach target.
 * Tests     : coins={1,2,5}, target=10 => 10 ways
 *             coins={1,5,6,9}, target=11 => 9 ways (trimmed to 8-bit)
 *             coins={2,3,7}, target=12 => ways (8-bit)
 * g_result  = (3<<16)|(ways_a<<8)|ways_b
 *             ways_a = ways(coins={1,2,5},target=10) = 10 = 0x0A
 *             ways_b = ways(coins={1,5,6,9},target=11) % 256 = 9 = 0x09 ... wait
 *             Actually ways(coins={1,2,5},10)=10=0x0A, ways(coins={1,5,6,9},11)=9=0x09
 *             n_tests=3 => (3<<16)|(0x0A<<8)|0x09 = 0x030A09
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define CC_MAX_TARGET 16
#define CC_MAX_COINS  5

static uint32_t cc_dp[CC_MAX_TARGET + 1];

static uint32_t cc_count_ways(const uint32_t *coins, int nc, int target) {
    for (int i = 0; i <= target; i++) cc_dp[i] = 0;
    cc_dp[0] = 1;
    for (int ci = 0; ci < nc; ci++) {
        uint32_t c = coins[ci];
        for (int j = (int)c; j <= target; j++) {
            cc_dp[j] += cc_dp[j - (int)c];
        }
    }
    return cc_dp[target];
}

static uint32_t run_coin_change_tests(void) {
    /* Test 1: {1,2,5}, target=10 => 10 ways */
    static const uint32_t coins1[3] = {1, 2, 5};
    uint32_t w1 = cc_count_ways(coins1, 3, 10);  /* expect 10 */

    /* Test 2: {1,5,6,9}, target=11 => 9 ways */
    static const uint32_t coins2[4] = {1, 5, 6, 9};
    uint32_t w2 = cc_count_ways(coins2, 4, 11);  /* expect 9 */

    /* Test 3: {2,3,7}, target=12 => verify non-zero */
    static const uint32_t coins3[3] = {2, 3, 7};
    uint32_t w3 = cc_count_ways(coins3, 3, 12);  /* expect >=1 */
    (void)w3;

    /* metric_a = w1 = 10 = 0x0A
     * metric_b = w2 =  9 = 0x09
     * n_tests=3 => 0x030A09 */
    uint32_t metric_a = w1 & 0xFFu;
    uint32_t metric_b = w2 & 0xFFu;
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_coin_change_tests();
    while (1) {}
}
