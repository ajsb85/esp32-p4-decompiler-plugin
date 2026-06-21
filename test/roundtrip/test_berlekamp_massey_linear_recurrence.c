/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Berlekamp-Massey Linear Recurrence fixture.
 *
 * The Berlekamp-Massey algorithm finds the shortest linear recurrence
 * (LFSR) that generates a given sequence over a field Z_p.
 *
 * Algorithm (working in Z_p arithmetic):
 *   1. Maintain current recurrence C, last-update polynomial B
 *   2. Compute discrepancy d = s[i] - sum(C[j]*s[i-j]) mod p
 *   3. If d != 0: update C via C[j+delta] -= (d/db)*B[j]; if 2L<=i grow L
 *
 * Distinctive decompiler idioms:
 *   1. Discrepancy accumulation: `d = (d + MOD - C[j]*s[i-j]%MOD) % MOD`
 *   2. Coefficient update: `C[j+delta] = (C[j+delta]+MOD-coeff*B[j]%MOD)%MOD`
 *   3. Length doubling check: `2*L <= i` decides if LFSR length grows
 *   4. Modular inverse via Fermat: `mod_pow(a, MOD-2, MOD)`
 *
 * Test sequence: Fibonacci mod 97 for 10 terms
 *   s = {1,1,2,3,5,8,13,21,34,55}
 *   BM over Z_97 yields LFSR length L=5
 *
 * Result encoding:
 *   lfsr_len = 5 = 0x05
 *   last_s   = s[9] & 0xFF = 55 = 0x37
 *   checksum = (5 + 55) & 0xFF = 60 = 0x3C
 *   g_result = (5<<16)|(55<<8)|60 = 0x05373C
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BM_MOD   97u
#define BM_N     10u
#define BM_MAXL  12u

static uint32_t mod_pow(uint32_t base, uint32_t exp, uint32_t mod)
{
    uint32_t result = 1u;
    base %= mod;
    while (exp > 0u) {
        if (exp & 1u) result = result * base % mod;
        base = base * base % mod;
        exp >>= 1u;
    }
    return result;
}

static uint32_t mod_inv(uint32_t a, uint32_t mod)
{
    return mod_pow(a, mod - 2u, mod);
}

void test_berlekamp_massey_linear_recurrence(void)
{
    /* Build sequence: Fibonacci mod 97 */
    uint32_t s[BM_N];
    s[0] = 1u;
    s[1] = 1u;
    for (uint32_t i = 2u; i < BM_N; i++) {
        s[i] = (s[i-1u] + s[i-2u]) % BM_MOD;
    }

    /* Berlekamp-Massey over Z_97 */
    uint32_t C[BM_MAXL];
    uint32_t B[BM_MAXL];
    for (uint32_t i = 0u; i < BM_MAXL; i++) { C[i] = 0u; B[i] = 0u; }
    C[0] = 1u;
    B[0] = 1u;

    uint32_t L     = 0u;
    uint32_t delta = 1u;
    uint32_t db    = 1u;

    for (uint32_t i = 0u; i < BM_N; i++) {
        /* Discrepancy: d = s[i] - sum_{j=1}^{L} C[j]*s[i-j]  mod p */
        uint32_t d = s[i];
        for (uint32_t j = 1u; j <= L; j++) {
            d = (d + BM_MOD - C[j] * s[i - j] % BM_MOD) % BM_MOD;
        }

        if (d == 0u) {
            delta++;
        } else {
            uint32_t T[BM_MAXL];
            for (uint32_t j = 0u; j < BM_MAXL; j++) T[j] = C[j];

            uint32_t coeff = d * mod_inv(db, BM_MOD) % BM_MOD;
            for (uint32_t j = 0u; j + delta < BM_MAXL; j++) {
                C[j + delta] = (C[j + delta] + BM_MOD - coeff * B[j] % BM_MOD) % BM_MOD;
            }

            if (2u * L <= i) {
                L     = i + 1u - L;
                db    = d;
                delta = 1u;
                for (uint32_t j = 0u; j < BM_MAXL; j++) B[j] = T[j];
            } else {
                delta++;
            }
        }
    }

    /* L=5, s[9]=55 */
    uint32_t lfsr_len = L & 0xFFu;
    uint32_t last_s   = s[BM_N - 1u] & 0xFFu;
    uint32_t checksum = (lfsr_len + last_s) & 0xFFu;
    g_result = (lfsr_len << 16) | (last_s << 8) | checksum;
}

__attribute__((noreturn)) void _start(void)
{
    test_berlekamp_massey_linear_recurrence();
    for (;;);
}
