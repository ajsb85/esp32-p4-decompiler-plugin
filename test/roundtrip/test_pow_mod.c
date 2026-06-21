/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Fast modular exponentiation round-trip fixture.
 *
 * Square-and-multiply (binary exponentiation) is one of the most recognizable
 * cryptographic decompiler idioms.  The key pattern:
 *
 *   while (exp > 0) {
 *       if (exp & 1) result = result * base % mod;   ← odd-bit multiply
 *       exp >>= 1;                                    ← right-shift exponent
 *       base = base * base % mod;                    ← square
 *   }
 *
 * Four test calls:
 *   pow_mod(2,  10, 1000) = 1024  % 1000 = 24
 *   pow_mod(3,   7,  100) = 2187  %  100 = 87
 *   pow_mod(5,   5,   31) = 3125  %   31 = 25
 *   pow_mod(7,   3,   13) =  343  %   13 =  5
 *
 *   sum = 24+87+25+5 = 141 = 0x8D
 *   xor = 24^87^25^5   = 83 = 0x53
 *   n   = 4
 *
 * g_result = (n << 16) | (sum << 8) | xor = 0x00048D53
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── pow_mod — O(log exp) ────────────────────────────────────────────────── */

static uint32_t pow_mod(uint32_t base, uint32_t exp, uint32_t mod)
{
    uint32_t result = 1u;
    base %= mod;
    while (exp > 0) {
        if (exp & 1u)
            result = result * base % mod;
        exp >>= 1u;
        base = base * base % mod;
    }
    return result;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_pow_mod(void)
{
    static const uint32_t bases[4] = {2, 3, 5, 7};
    static const uint32_t exps[4]  = {10, 7, 5, 3};
    static const uint32_t mods[4]  = {1000, 100, 31, 13};

    const int n = 4;
    uint32_t sum_r = 0, xor_r = 0;
    for (int i = 0; i < n; i++) {
        uint32_t r = pow_mod(bases[i], exps[i], mods[i]);
        sum_r += r;
        xor_r ^= r;
    }

    g_result = ((uint32_t)n << 16)
             | (sum_r << 8)
             | (xor_r & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_pow_mod();
    for (;;);
}
