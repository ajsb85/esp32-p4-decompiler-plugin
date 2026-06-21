/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Decode Ways (1D DP) fixture.
 *
 * Counts the number of ways to decode a digit string into letters
 * where 'A'=1, 'B'=2, ..., 'Z'=26. Uses 1D DP with 2 recurrences.
 *
 * Distinctive decompiler idioms:
 *   1. `dp[0]=1; dp[1]=(s[0]!='0')?1:0` — DP base cases
 *   2. `if(s[i-1]!='0') dp[i]+=dp[i-1]` — single-char decode
 *   3. `t=(s[i-2]-'0')*10+(s[i-1]-'0'); if(t>=10&&t<=26) dp[i]+=dp[i-2]` — two-char
 *
 * Strings: "226"→3, "12"→2, "11106"→2, "10"→1 (n_strings=4)
 * sum_ways=8, w[0]=3, w[1]^w[2]^w[3]=2^2^1=1
 *
 * g_result = (sum_ways<<16)|(w[0]<<8)|(w[1]^w[2]^w[3]) = 0x00080301
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_decode_ways(void)
{
    static const char *strs[4] = {"226", "12", "11106", "10"};
    static const int ns[4] = {3, 2, 5, 2};
    int dp[8], ways[4];
    int s, i;

    for (s = 0; s < 4; s++) {
        int n = ns[s];
        const char *str = strs[s];
        dp[0] = 1;
        dp[1] = (str[0] != '0') ? 1 : 0;
        for (i = 2; i <= n; i++) {
            dp[i] = 0;
            if (str[i-1] != '0') dp[i] += dp[i-1];
            int t = (str[i-2] - '0') * 10 + (str[i-1] - '0');
            if (t >= 10 && t <= 26) dp[i] += dp[i-2];
        }
        ways[s] = dp[n];
    }
    /* ways={3,2,2,1}, sum=8, w[0]=3, w[1]^w[2]^w[3]=1 */
    int sum = ways[0] + ways[1] + ways[2] + ways[3];
    g_result = ((uint32_t)sum << 16)
             | ((uint32_t)ways[0] << 8)
             | (uint32_t)(ways[1] ^ ways[2] ^ ways[3]);
}

__attribute__((noreturn)) void _start(void)
{
    test_decode_ways();
    for (;;);
}
