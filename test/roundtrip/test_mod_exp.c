/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Modular Exponentiation (binary method) fixture.
 *
 * Computes base^exp % mod using the fast binary exponentiation:
 * while(exp > 0): if(exp&1) result = result*base % mod; base = base*base % mod; exp >>= 1
 *
 * Distinctive decompiler idioms:
 *   1. `exp >>= 1` — right-shift exponent each iteration
 *   2. `if (exp & 1)` — test LSB for odd exponent
 *   3. `result = result * base % mod` — modular multiplication
 *
 * Test cases:
 *   2^10 % 1000 = 24
 *   3^7  % 100  = 87
 *   5^5  % 113  = 74
 *
 * n_tests=3, sum=24+87+74=185=0xB9, xor=24^87^74=5=0x05
 * g_result = (3 << 16) | (185 << 8) | 5 = 0x0003B905
 */
#include <stdint.h>

volatile uint32_t g_result;

static uint32_t me_pow(uint32_t base, uint32_t exp, uint32_t mod)
{
    uint32_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1u) result = result * base % mod;
        base = base * base % mod;
        exp >>= 1;
    }
    return result;
}

void test_mod_exp(void)
{
    uint32_t r0 = me_pow(2,  10, 1000); /* 24 */
    uint32_t r1 = me_pow(3,   7, 100);  /* 87 */
    uint32_t r2 = me_pow(5,   5, 113);  /* 74 */

    uint32_t sum = r0 + r1 + r2;        /* 185 */
    uint32_t xr  = r0 ^ r1 ^ r2;       /* 5   */

    g_result = (3u << 16) | ((sum & 0xFFu) << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_mod_exp();
    for (;;);
}
