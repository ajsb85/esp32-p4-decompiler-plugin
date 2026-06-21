/*
 * test_bracket_sequence_dp.c
 * Bracket sequence DP: count valid bracket sequences, find minimum removals,
 * and compute the number of ways to parenthesize an expression.
 *
 * Problems covered:
 * 1. Count valid bracket sequences of length 2n (Catalan numbers via DP).
 *    dp[i][j] = number of ways with i chars remaining and j unmatched '('.
 *    C(n) = dp[2n][0] where we add '(' or ')'.
 *
 * 2. Minimum bracket removals to make a string valid:
 *    Scan left-to-right tracking open count; count mismatched ')' as we go.
 *
 * 3. Bracket DP for matrix chain-like parenthesization counting (Catalan).
 *    Number of ways to fully parenthesize n+1 factors = C(n).
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BSQ_MAXN 12

/* Count valid bracket sequences of length 2*n via DP.
 * dp[j] = number of prefixes of length (current) with j unmatched '('
 * Catalan: C(n) = C(2n,n)/(n+1)
 */
static uint32_t bracket_seq_count(uint32_t n) {
    /* dp[j] = count with j unmatched opens; length up to 2n */
    uint32_t dp[BSQ_MAXN + 1];
    for (int j = 0; j <= BSQ_MAXN; j++) dp[j] = 0u;
    dp[0] = 1u; /* empty sequence */

    for (uint32_t step = 0u; step < 2u * n; step++) {
        uint32_t ndp[BSQ_MAXN + 1];
        for (int j = 0; j <= BSQ_MAXN; j++) ndp[j] = 0u;
        for (int j = 0; j <= (int)n; j++) {
            if (dp[j] == 0u) continue;
            /* Add '(' */
            if (j + 1 <= (int)n) ndp[j + 1] += dp[j];
            /* Add ')' if j > 0 */
            if (j > 0) ndp[j - 1] += dp[j];
        }
        for (int j = 0; j <= BSQ_MAXN; j++) dp[j] = ndp[j];
    }
    return dp[0];
}

/* Minimum removals to make bracket string valid.
 * Returns count of unmatched brackets (open + unmatched close).
 */
static uint32_t bracket_min_removals(const uint8_t *s, uint32_t len) {
    uint32_t open = 0u;   /* unmatched '(' */
    uint32_t close = 0u;  /* unmatched ')' */
    for (uint32_t i = 0u; i < len; i++) {
        if (s[i] == (uint8_t)'(') {
            open++;
        } else {
            if (open > 0u) open--;
            else close++;
        }
    }
    return open + close;
}

/* Parenthesization count for n+1 factors = Catalan(n).
 * Use recurrence: P(1)=1, P(n)=sum_{k=1}^{n-1} P(k)*P(n-k) for n>1.
 */
static uint32_t parenthesization_count(uint32_t n) {
    uint32_t p[BSQ_MAXN + 2];
    p[0] = 0u; p[1] = 1u;
    for (uint32_t i = 2u; i <= n; i++) {
        p[i] = 0u;
        for (uint32_t k = 1u; k < i; k++) {
            p[i] += p[k] * p[i - k];
        }
    }
    return (n >= 1u) ? p[n] : 1u;
}

static uint32_t run_bracket_seq_tests(void) {
    uint32_t n_tests = 0u;

    /*
     * Test 1: Count valid sequences of length 2*3 = 6: C(3) = 5.
     */
    uint32_t c3 = bracket_seq_count(3u);
    n_tests++;
    /* c3 == 5 */

    /*
     * Test 2: Count valid sequences of length 2*4 = 8: C(4) = 14.
     */
    uint32_t c4 = bracket_seq_count(4u);
    n_tests++;
    /* c4 == 14 */

    /*
     * Test 3: Min removals for "(()" = 1 unmatched '('.
     */
    const uint8_t s3[] = {'(', '(', ')'};
    uint32_t rem3 = bracket_min_removals(s3, 3u);
    n_tests++;
    /* rem3 == 1 */

    /*
     * Test 4: Min removals for ")(" = 2 (one unmatched ')' + one unmatched '(').
     */
    const uint8_t s4[] = {')', '('};
    uint32_t rem4 = bracket_min_removals(s4, 2u);
    n_tests++;
    /* rem4 == 2 */

    /*
     * Test 5: Parenthesization for 5 factors (n=4): P(4) = C(3) = 5.
     */
    uint32_t par4 = parenthesization_count(4u);
    n_tests++;
    /* par4 == 5 */

    /*
     * Pack result:
     * n_tests = 5 = 0x05
     * metric_a: c3=5, c4=14 -> (c3 << 4) | (c4 & 0xF) = 80|14 = 94 = 0x5E
     * metric_b: (rem3 << 5) | (rem4 << 3) | (par4 & 0x7)
     *         = (1<<5)|(2<<3)|(5&7) = 32|16|5 = 53 = 0x35
     * Result = (5<<16)|(0x5E<<8)|0x35 = 0x055E35
     * Bytes: 0x05, 0x5E, 0x35 — non-zero, distinct.
     */
    uint32_t metric_a = (c3 << 4) | (c4 & 0xFu);
    uint32_t metric_b = (rem3 << 5) | (rem4 << 3) | (par4 & 0x7u);
    return (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_bracket_seq_tests();
    while (1) {}
}
