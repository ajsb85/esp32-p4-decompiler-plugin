/*
 * test_longest_valid_parens.c — length of longest valid parentheses substring.
 *
 * dp[i] = length of longest valid parens ending at i
 * If s[i]==')':
 *   if s[i-1]=='(': dp[i] = dp[i-2] + 2
 *   if s[i-1]==')' and s[i-dp[i-1]-1]=='(': dp[i] = dp[i-1]+2+dp[i-dp[i-1]-2]
 *
 * Tests:
 *  "(()": longest=2
 *  ")()())": longest=4
 *  "": longest=0
 *
 * n_tests=3, sum=2+4+0=6, xor=2^4^0=6
 * g_result = (3<<16)|(6<<8)|6 = 0x00030606
 */
#include <stdint.h>

#define MAXLEN 32

static int slen(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static int longest_valid_parens(const char *s)
{
    int n = slen(s);
    if (n == 0) return 0;
    int dp[MAXLEN];
    for (int i = 0; i < n; i++) dp[i] = 0;
    int best = 0;
    for (int i = 1; i < n; i++) {
        if (s[i] == ')') {
            if (s[i-1] == '(') {
                dp[i] = (i >= 2 ? dp[i-2] : 0) + 2;
            } else if (dp[i-1] > 0) {
                int j = i - dp[i-1] - 1;
                if (j >= 0 && s[j] == '(') {
                    dp[i] = dp[i-1] + 2 + (j >= 1 ? dp[j-1] : 0);
                }
            }
            if (dp[i] > best) best = dp[i];
        }
    }
    return best;
}

volatile uint32_t g_result;

int main(void)
{
    int r0 = longest_valid_parens("(()");
    int r1 = longest_valid_parens(")()())");
    int r2 = longest_valid_parens("");

    int sum = r0 + r1 + r2;
    uint32_t xor_res = (uint32_t)(r0 ^ r1 ^ r2);

    g_result = (3u << 16) | ((uint32_t)sum << 8) | (xor_res & 0xFFu);
    /* expected: (3<<16)|(6<<8)|6 = 0x00030606 */
    return 0;
}
