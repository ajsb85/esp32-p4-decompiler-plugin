/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Barrett modular reduction fixture.
 *
 * Barrett reduction replaces expensive division by precomputing a reciprocal
 * approximation.  For modulus m precompute:
 *   shift  = 2 * ceil(log2(m))
 *   factor = (1 << shift) / m
 *
 * Then for value x:
 *   q = (x * factor) >> shift
 *   r = x - q * m
 *   if (r >= m) r -= m        (at most one correction)
 *
 * We use a 32-bit Barrett variant (shift = 32):
 *   factor = (1ULL << 32) / m   (precomputed as 64-bit)
 *   q      = (uint32_t)(((uint64_t)x * factor) >> 32)
 *   r      = x - q * m
 *   if (r >= m) r -= m
 *
 * Three test cases (modulus, value, expected remainder):
 *   m=97,  x=123456  => r = 123456 % 97  = 72
 *   m=251, x=987654  => r = 987654 % 251 = 220
 *   m=199, x=314159  => r = 314159 % 199 = 137
 *
 * n_tests  = 3
 * sum_r = 72 + 220 + 137 = 429 => low byte 0xAD
 * xor_r = 72 ^ 220 ^ 137 = 29  = 0x1D
 *
 * g_result = (n_tests << 16) | (sum_r & 0xFF << 8) | xor_r = 0x0003AD1D
 */

typedef unsigned int uint;
typedef unsigned long long uint64;

extern volatile unsigned g_result;

/* ── Barrett precomputed structure ────────────────────────────────────────── */

typedef struct {
    uint m;       /* modulus */
    uint64 factor; /* floor((1<<32) / m) */
} Barrett;

static Barrett barrett_init(uint m)
{
    Barrett b;
    b.m      = m;
    b.factor = ((uint64)1 << 32) / m;
    return b;
}

static uint barrett_reduce(Barrett b, uint x)
{
    uint q = (uint)(((uint64)x * b.factor) >> 32);
    uint r = x - q * b.m;
    if (r >= b.m)
        r -= b.m;
    return r;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_barrett_reduction(void)
{
    static const uint mods[] = {97,  251,   199};
    static const uint vals[] = {123456, 987654, 314159};

    uint sum_r = 0, xor_r = 0;
    for (uint k = 0; k < 3; k++) {
        Barrett b = barrett_init(mods[k]);
        uint r = barrett_reduce(b, vals[k]);
        sum_r += r;
        xor_r ^= r;
    }

    g_result = (3u << 16) | ((sum_r & 0xFFu) << 8) | (xor_r & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_barrett_reduction();
    for (;;);
}
