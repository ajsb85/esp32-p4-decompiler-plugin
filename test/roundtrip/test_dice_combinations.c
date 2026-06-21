/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Dice Combinations / Number of Dice Rolls with Target Sum.
 *
 * 2D DP: dp[i][j] = number of ways to get sum j using i dice with f faces.
 * Recurrence: dp[i][j] = sum(dp[i-1][j-k] for k in 1..f)
 *
 * Distinctive decompiler idioms:
 *   1. `dp[0][0]=1` — base: 0 dice give sum 0 in 1 way
 *   2. `for(i=1;i<=d;i++) for(j=i;j<=i*f&&j<=t;j++) for(k=1;k<=f&&k<=j;k++)`
 *   3. `dp[i][j]+=dp[i-1][j-k]` — accumulate from previous dice row
 *
 * Test 1: d=3 dice, f=6 faces, target=7 → 15 ways
 * Test 2: d=2 dice, f=6 faces, target=7 → 6 ways
 *
 * g_result = (2<<16)|(ways1<<8)|ways2 = 0x00020F06
 */
#include <stdint.h>

volatile uint32_t g_result;

__attribute__((optimize("O1")))
void test_dice_combinations(void)
{
    static int dp[4][22];
    int i, j, k;

    /* Test 1: d=3, f=6, target=7 */
    for (i = 0; i <= 3; i++) for (j = 0; j <= 21; j++) dp[i][j] = 0;
    dp[0][0] = 1;
    for (i = 1; i <= 3; i++)
        for (j = i; j <= i*6 && j <= 7; j++)
            for (k = 1; k <= 6 && k <= j; k++)
                dp[i][j] += dp[i-1][j-k];
    int ways1 = dp[3][7];

    /* Test 2: d=2, f=6, target=7 */
    for (i = 0; i <= 2; i++) for (j = 0; j <= 12; j++) dp[i][j] = 0;
    dp[0][0] = 1;
    for (i = 1; i <= 2; i++)
        for (j = i; j <= i*6 && j <= 7; j++)
            for (k = 1; k <= 6 && k <= j; k++)
                dp[i][j] += dp[i-1][j-k];
    int ways2 = dp[2][7];

    /* ways1=15=0x0F, ways2=6 */
    g_result = (2u << 16)
             | ((uint32_t)ways1 << 8)
             | (uint32_t)ways2;
}

__attribute__((noreturn)) void _start(void)
{
    test_dice_combinations();
    for (;;);
}
