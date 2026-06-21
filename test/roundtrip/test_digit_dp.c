/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Digit DP (count numbers by digit-sum mod k) fixture.
 *
 * Digit DP counts integers in [1..N] satisfying a digit-level constraint
 * without iterating all N numbers.  The recursive formulation:
 *   count(pos, rem, tight) = sum over allowed digits d at position pos
 *     of count(pos+1, (rem+d)%k, tight && d==limit[pos])
 *
 * Distinctive decompiler idioms:
 *   1. `if (pos == n_digits) return rem == 0 ? 1 : 0` — base case
 *   2. `int limit = tight ? digits[pos] : 9` — tight bound on current digit
 *   3. `for d in [0..limit]: count += solve(pos+1, (rem+d)%k, tight&&d==limit)`
 *   4. `memo[pos][rem][tight]` — memoisation (or iterative table)
 *
 * Queries:
 *   count([1..100], digit_sum % 3 == 0) = 33   (all multiples of 3 ≡ digit-sum mod 3)
 *   count([1..100], digit_sum % 5 == 0) = 19
 *
 * n_queries = 2
 * sum       = 33+19 = 52 (0x34)
 * xor       = 33^19 = 50 (0x32)
 *
 * g_result = (n_queries << 16) | (sum << 8) | xor = 0x00023432
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Digit DP ────────────────────────────────────────────────────────────── */

#define DD_MAXD 3   /* max digits in N=100 */
#define DD_MAXK 10  /* max modulus */

static int dd_digits[DD_MAXD];
static int dd_n_dig;
static int dd_k;
static int dd_memo[DD_MAXD][DD_MAXK][2];
static int dd_memo_set[DD_MAXD][DD_MAXK][2];

static int dd_solve(int pos, int rem, int tight)
{
    if (pos == dd_n_dig) return rem == 0 ? 1 : 0;
    if (dd_memo_set[pos][rem][tight]) return dd_memo[pos][rem][tight];
    int lim = tight ? dd_digits[pos] : 9;
    int cnt = 0;
    for (int d = 0; d <= lim; d++)
        cnt += dd_solve(pos + 1, (rem + d) % dd_k, tight && (d == lim));
    dd_memo[pos][rem][tight] = cnt;
    dd_memo_set[pos][rem][tight] = 1;
    return cnt;
}

static int count_digit_sum_mod(int n, int k)
{
    /* Decompose n into digits */
    dd_n_dig = 0;
    int tmp = n;
    while (tmp > 0) { dd_digits[dd_n_dig++] = tmp % 10; tmp /= 10; }
    /* Reverse to MSB-first */
    for (int l = 0, r = dd_n_dig - 1; l < r; l++, r--) {
        int t = dd_digits[l]; dd_digits[l] = dd_digits[r]; dd_digits[r] = t;
    }
    dd_k = k;
    for (int i = 0; i < dd_n_dig; i++)
        for (int j = 0; j < k; j++)
            dd_memo_set[i][j][0] = dd_memo_set[i][j][1] = 0;

    /* count([0..n], sum%k==0) — subtract 1 for n=0 */
    int total = dd_solve(0, 0, 1) - 1; /* subtract the n=0 case */
    return total;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_digit_dp(void)
{
    int c3 = count_digit_sum_mod(100, 3);  /* 33 */
    int c5 = count_digit_sum_mod(100, 5);  /* 19 */

    uint32_t s = (uint32_t)(c3 + c5);  /* 52 */
    uint32_t x = (uint32_t)(c3 ^ c5);  /* 50 */

    g_result = (2u << 16) | ((s & 0xFFu) << 8) | (x & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_digit_dp();
    for (;;);
}
