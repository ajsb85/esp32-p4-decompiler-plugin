/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Euler's Totient function (prime-factorisation) fixture.
 *
 * Compute φ(n) via iterative prime factorisation:
 *   result = n
 *   for p = 2 while p*p <= n:
 *       if n % p == 0:
 *           result -= result / p      (multiply by 1-1/p)
 *           while n % p == 0: n /= p  (strip all factors of p)
 *   if n > 1: result -= result / n    (remaining prime factor)
 *
 * Distinctive decompiler idioms:
 *   1. `while (n % p == 0) n /= p` — strip prime power (repeated trial division)
 *   2. `result -= result / p`       — Euler product formula step
 *   3. `p * p <= n` loop bound       — trial division up to √n
 *   4. `if (n > 1) result -= result / n` — handle final prime > √original_n
 *
 * Tests: φ(12)=4, φ(13)=12, φ(36)=12, φ(100)=40
 *
 * n_tests  = 4
 * sum      = 4+12+12+40 = 68  = 0x44
 * xor      = 4^12^12^40 = 44  = 0x2C
 *
 * g_result = (n_tests << 16) | (sum << 8) | xor = 0x0004442C
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Euler's totient ─────────────────────────────────────────────────────────── */

static int euler_phi(int n)
{
    int result = n;
    for (int p = 2; p * p <= n; p++) {
        if (n % p == 0) {
            result -= result / p;        /* multiply by (1 - 1/p) */
            while (n % p == 0) n /= p;  /* strip all p factors   */
        }
    }
    if (n > 1) result -= result / n;     /* remaining prime       */
    return result;
}

/* ── Test entry point ────────────────────────────────────────────────────────── */

void test_euler_totient(void)
{
    static const int et_vals[4] = {12, 13, 36, 100};
    uint32_t sum = 0, xor_val = 0;
    for (int i = 0; i < 4; i++) {
        uint32_t p = (uint32_t)euler_phi(et_vals[i]);
        sum     += p;
        xor_val ^= p;
    }
    /* sum=68, xor_val=44 */
    g_result = (4u << 16) | (sum << 8) | (xor_val & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_euler_totient();
    for (;;);
}
