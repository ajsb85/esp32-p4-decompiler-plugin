/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Pollard's Rho Integer Factorization fixture.
 *
 * Pollard's rho algorithm finds a non-trivial factor of n by detecting a
 * cycle in the pseudo-random sequence x_{i+1} = (x_i² + c) mod n using
 * Floyd's cycle detection algorithm.
 *
 * Distinctive decompiler idioms:
 *   1. `y = f(f(y, c, n), c, n)` — double-step hare (Floyd cycle)
 *   2. `d = gcd(|x - y|, n)` — GCD of absolute difference with n
 *   3. `x = f(x, c, n)` — tortoise single step
 *   4. `return (long long)x * x % n + c` — quadratic polynomial mod n
 *
 * Test case: n = 77 = 7 × 11
 *   Starting with x=2, y=2, c=1:
 *     Step 1: x=f(2)=5, y=f(f(2))=f(5)=26, d=gcd(|26-5|,77)=gcd(21,77)=7 ≠ 1
 *   → factor found: 7, other factor: 11
 *
 * n_factors_found = 2
 * smaller_factor  = 7  = 0x07
 * larger_factor   = 11 = 0x0B
 *
 * g_result = (n_factors << 16) | (factor_a << 8) | factor_b = 0x0002070B
 */
#include <stdint.h>

volatile uint32_t g_result;

static int pr_gcd(int a, int b)
{
    while (b) { int t = b; b = a % b; a = t; }
    return a;
}

static int pr_abs(int x) { return x < 0 ? -x : x; }

/* f(x) = (x*x + c) mod n */
static int pr_f(int x, int c, int n)
{
    return (int)(((long long)x * x + c) % n);
}

/* Returns a non-trivial factor of n, or -1 if failed (cycle found = n). */
static int pollard_rho(int n, int c)
{
    int x = 2, y = 2, d = 1;
    while (d == 1) {
        x = pr_f(x, c, n);
        y = pr_f(pr_f(y, c, n), c, n);
        d = pr_gcd(pr_abs(x - y), n);
    }
    return (d < n) ? d : -1;
}

void test_pollard_rho(void)
{
    int n = 77;
    int factor_a = pollard_rho(n, 1);   /* 7 */
    int factor_b = n / factor_a;         /* 11 */

    /* Ensure factor_a ≤ factor_b */
    if (factor_a > factor_b) { int t = factor_a; factor_a = factor_b; factor_b = t; }

    g_result = (2u << 16)
             | ((uint32_t)factor_a << 8)
             | ((uint32_t)factor_b & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_pollard_rho();
    for (;;);
}
