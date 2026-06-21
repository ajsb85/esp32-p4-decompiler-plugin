/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Chinese Remainder Theorem (Garner / direct construction) fixture.
 *
 * Given a system of simultaneous congruences  x ≡ r_i (mod m_i)
 * with pairwise coprime moduli, the unique solution mod M = ∏m_i is:
 *   x = Σ r_i * M_i * inv(M_i, m_i)  (mod M)
 * where M_i = M / m_i and inv(a, m) is the modular inverse of a mod m.
 *
 * Distinctive decompiler idioms:
 *   1. `M = m[0]*m[1]*...`                — compute big product
 *   2. `M_i = M / m[i]`                   — partial product
 *   3. `inv = mod_inv(M_i % m[i], m[i])`  — extended-GCD modular inverse
 *   4. `x = (x + r[i] * M_i * inv) % M`   — accumulate contribution
 *
 * Three CRT instances:
 *   1. x ≡ 2(mod 3), x ≡ 3(mod 5), x ≡ 2(mod 7)   → x = 23
 *   2. x ≡ 1(mod 2), x ≡ 2(mod 3), x ≡ 4(mod 5)   → x = 29
 *   3. x ≡ 3(mod 4), x ≡ 5(mod 7)                  → x = 19
 *
 * n_tests = 3
 * sum     = 23+29+19 = 71 = 0x47
 * xor     = 23^29^19 = 25 = 0x19
 *
 * g_result = (n_tests << 16) | (sum << 8) | xor = 0x00034719
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Modular inverse (iterative extended GCD) ───────────────────────────────── */

static int mod_inv(int a, int m)
{
    int m0 = m, x0 = 0, x1 = 1;
    if (m == 1) return 0;
    while (a > 1) {
        int q = a / m;
        int t = m;
        m  = a % m;
        a  = t;
        t  = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    return x1 < 0 ? x1 + m0 : x1;
}

/* ── CRT solver (k congruences, pairwise coprime moduli) ────────────────────── */

static int crt_solve(const int *r, const int *m, int k)
{
    int M = 1;
    for (int i = 0; i < k; i++) M *= m[i];
    int x = 0;
    for (int i = 0; i < k; i++) {
        int Mi  = M / m[i];
        int inv = mod_inv(Mi % m[i], m[i]);
        x = (x + r[i] * Mi * inv) % M;
    }
    return x;
}

/* ── Test entry point ────────────────────────────────────────────────────────── */

void test_crt(void)
{
    static const int r1[3] = {2, 3, 2};
    static const int m1[3] = {3, 5, 7};   /* M=105 */

    static const int r2[3] = {1, 2, 4};
    static const int m2[3] = {2, 3, 5};   /* M=30  */

    static const int r3[2] = {3, 5};
    static const int m3[2] = {4, 7};      /* M=28  */

    int c1 = crt_solve(r1, m1, 3); /* 23 */
    int c2 = crt_solve(r2, m2, 3); /* 29 */
    int c3 = crt_solve(r3, m3, 2); /* 19 */

    uint32_t sum     = (uint32_t)(c1 + c2 + c3);
    uint32_t xor_val = (uint32_t)(c1 ^ c2 ^ c3);
    /* sum=71, xor=25 */
    g_result = (3u << 16) | (sum << 8) | (xor_val & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_crt();
    for (;;);
}
