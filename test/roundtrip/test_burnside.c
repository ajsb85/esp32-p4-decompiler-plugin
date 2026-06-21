/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Burnside's Lemma (Necklace Counting) fixture.
 *
 * Counts distinct k-color n-bead necklaces using Burnside's lemma:
 *
 *   N(n, k) = (1/n) * Σ_{d | n} φ(d) * k^(n/d)
 *
 * where φ(d) is Euler's totient function and d ranges over divisors of n.
 *
 * Distinctive decompiler idioms:
 *   1. `for (d = 1; d <= n; d++) if (n % d == 0)` — divisor enumeration
 *   2. `total += euler_phi(d) * int_pow(k, n/d)` — per-divisor contribution
 *   3. `n_distinct = total / n` — Burnside averaging
 *   4. `result -= result / p` — multiplicative Euler phi update
 *
 * Test: n=6 beads, k=2 colors
 *   Divisors of 6: {1, 2, 3, 6}
 *   d=1: φ(1)*2^6  = 1*64  = 64
 *   d=2: φ(2)*2^3  = 1*8   = 8
 *   d=3: φ(3)*2^2  = 2*4   = 8
 *   d=6: φ(6)*2^1  = 2*2   = 4
 *   Sum = 84 → N(6,2) = 84/6 = 14
 *
 * n_beads    = 6
 * n_colors   = 2
 * n_necklace = 14 = 0x0E
 *
 * g_result = (n_beads << 16) | (n_colors << 8) | n_necklace = 0x0006020E
 */
#include <stdint.h>

volatile uint32_t g_result;

static int bsn_euler_phi(int n)
{
    int result = n;
    for (int p = 2; (long long)p * p <= n; p++) {
        if (n % p == 0) {
            while (n % p == 0) n /= p;
            result -= result / p;
        }
    }
    if (n > 1) result -= result / n;
    return result;
}

static int bsn_int_pow(int base, int exp)
{
    int result = 1;
    while (exp > 0) {
        if (exp & 1) result *= base;
        base *= base;
        exp >>= 1;
    }
    return result;
}

static int burnside_necklace(int n, int k)
{
    int total = 0;
    for (int d = 1; d <= n; d++) {
        if (n % d == 0) {
            total += bsn_euler_phi(d) * bsn_int_pow(k, n / d);
        }
    }
    return total / n;
}

void test_burnside(void)
{
    int n = 6, k = 2;
    int n_necklace = burnside_necklace(n, k);  /* 14 */

    g_result = ((uint32_t)n           << 16)
             | ((uint32_t)k           << 8)
             | ((uint32_t)n_necklace & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_burnside();
    for (;;);
}
