/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — House Robber (linear DP) fixture.
 *
 * Classic DP: rob non-adjacent houses to maximise total loot.
 * Recurrence: dp[i] = max(dp[i-2] + arr[i], dp[i-1])
 * Space-optimised using two rolling variables (prev2, prev1).
 *
 * Distinctive decompiler idioms:
 *   1. `cur = prev2 + arr[i] > prev1 ? prev2 + arr[i] : prev1` — max without branch
 *   2. `prev2 = prev1; prev1 = cur` — rolling update
 *   3. Init: `prev2 = prev1 = 0` — base cases for empty prefix
 *
 * Test arrays → max profits:
 *   {1,2,3,1}       → 4   (rob index 0 and 2: 1+3)
 *   {2,7,9,3,1}     → 12  (rob index 0, 2, 4: 2+9+1)
 *   {2,1,1,2}       → 4   (rob index 0 and 3: 2+2)
 *
 * n_tests   = 3
 * sum_profit = 4+12+4 = 20  (0x14)
 * xor_profit = 4^12^4  = 12  (0x0C)
 *
 * g_result = (3 << 16) | (20 << 8) | 12 = 0x0003140C
 */
#include <stdint.h>

volatile uint32_t g_result;

#define HR_N1 4
#define HR_N2 5
#define HR_N3 4

static const int hr_arr1[HR_N1] = {1, 2, 3, 1};
static const int hr_arr2[HR_N2] = {2, 7, 9, 3, 1};
static const int hr_arr3[HR_N3] = {2, 1, 1, 2};

static int hr_rob(const int *arr, int n)
{
    int prev2 = 0, prev1 = 0;
    for (int i = 0; i < n; i++) {
        int cur = prev2 + arr[i] > prev1 ? prev2 + arr[i] : prev1;
        prev2 = prev1;
        prev1 = cur;
    }
    return prev1;
}

void test_house_robber(void)
{
    int r1 = hr_rob(hr_arr1, HR_N1);
    int r2 = hr_rob(hr_arr2, HR_N2);
    int r3 = hr_rob(hr_arr3, HR_N3);

    /* r1=4, r2=12, r3=4 */
    uint32_t sum_p = (uint32_t)(r1 + r2 + r3); /* 20 */
    uint32_t xor_p = (uint32_t)(r1 ^ r2 ^ r3); /* 12 */

    g_result = (3u << 16) | ((sum_p & 0xFFu) << 8) | (xor_p & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_house_robber();
    for (;;);
}
