/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Climbing Stairs DP (1 or 2 steps).
 *
 * Counts distinct ways to climb n stairs taking 1 or 2 steps.
 * Classic 1D DP: dp[n] = dp[n-1] + dp[n-2] (Fibonacci-like).
 *
 * Distinctive decompiler idioms:
 *   1. `dp[0]=1; dp[1]=1` — base: 1 way each for 0 and 1 stairs
 *   2. `for(i=2;i<=n;i++) dp[i]=dp[i-1]+dp[i-2]` — Fib recurrence
 *   3. Sum of ways[5..8] and encode ways[8]%32 for low byte
 *
 * Sequence dp[0..8]: 1,1,2,3,5,8,13,21,34
 * n_terms=4 (dp[5..8]), sum=8+13+21+34=76=0x4C, dp[8]%32=34%32=2
 *
 * g_result = (4<<16)|(sum&0xFF<<8)|(dp[8]%32) = 0x00044C02
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_climbing_stairs(void)
{
    int dp[9];
    dp[0] = 1; dp[1] = 1;
    for (int i = 2; i <= 8; i++) dp[i] = dp[i-1] + dp[i-2];

    int sum = dp[5] + dp[6] + dp[7] + dp[8];
    /* sum=76=0x4C, dp[8]=34, 34%32=2 */
    g_result = (4u << 16)
             | (((uint32_t)sum & 0xFFu) << 8)
             | (uint32_t)(dp[8] % 32);
}

__attribute__((noreturn)) void _start(void)
{
    test_climbing_stairs();
    for (;;);
}
