/*
 * test_min_cost_staircase.c — minimum cost to climb to top of staircase.
 *
 * dp[i] = cost[i] + min(dp[i-1], dp[i-2])
 * answer = min(dp[n-1], dp[n-2])  (can start from step 0 or 1)
 *
 * Tests:
 *  {10,15,20}              → 15
 *  {1,100,1,1,1,100,1,1,100,1} → 6
 *  {0,2,2,1}               → 2
 *
 * n_tests=3, sum=23=0x17, xor=15^6^2=11=0x0B
 * g_result = (3<<16)|(23<<8)|11 = 0x0003170B
 */
#include <stdint.h>

#define MAXLEN 16

static int min_cost_stair(const int *cost, int n)
{
    int dp[MAXLEN];
    dp[0] = cost[0];
    if (n == 1) return dp[0];
    dp[1] = cost[1];
    for (int i = 2; i < n; i++) {
        int prev = dp[i-1] < dp[i-2] ? dp[i-1] : dp[i-2];
        dp[i] = cost[i] + prev;
    }
    return dp[n-1] < dp[n-2] ? dp[n-1] : dp[n-2];
}

volatile uint32_t g_result;

int main(void)
{
    static const int c0[] = {10,15,20};
    static const int c1[] = {1,100,1,1,1,100,1,1,100,1};
    static const int c2[] = {0,2,2,1};

    int r0 = min_cost_stair(c0, 3);
    int r1 = min_cost_stair(c1, 10);
    int r2 = min_cost_stair(c2, 4);

    int sum = r0 + r1 + r2;
    uint32_t xor_res = (uint32_t)(r0 ^ r1 ^ r2);

    g_result = (3u << 16) | ((uint32_t)sum << 8) | (xor_res & 0xFFu);
    /* expected: (3<<16)|(23<<8)|11 = 0x0003170B */
    return 0;
}
