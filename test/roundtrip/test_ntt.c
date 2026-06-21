/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Number Theoretic Transform (NTT) fixture.
 *
 * Computes the NTT of a length-4 sequence modulo a small prime p = 17
 * using the naive O(n²) DFT formulation (pedagogical; real NTT uses butterfly).
 *
 * NTT definition (forward):
 *   X[k] = Σ_{j=0}^{n-1} a[j] * w^{jk}  mod p
 * where w = g^{(p-1)/n} mod p is a primitive n-th root of unity.
 *
 * Parameters:
 *   p = 17 (prime), n = 4, g = 3 (primitive root of 17)
 *   w = g^{(p-1)/n} = 3^4 = 81 mod 17 = 13
 *   Verify: 13^2 = 169 ≡ -1 mod 17, 13^4 ≡ 1 mod 17 ✓
 *
 * Distinctive decompiler idioms:
 *   1. `ntt_pow(base, exp, mod)` — fast modular exponentiation
 *   2. `sum = (sum + a[j] * ntt_pow(w, k*j, p)) % p` — modular DFT sum
 *   3. Fixed modulus 17 with primitive root 13 (specific constants)
 *   4. Inner loop over j, outer loop over k — DFT traversal pattern
 *
 * Input: a = [1, 2, 3, 4]
 * Output (NTT mod 17, w=13):
 *   X[0] = (1+2+3+4) mod 17          = 10
 *   X[1] = (1 + 2*13 + 3*16 + 4*4) mod 17 = 91 mod 17  = 6
 *   X[2] = (1 + 2*16 + 3*1 + 4*16) mod 17 = 100 mod 17 = 15
 *   X[3] = (1 + 2*4 + 3*16 + 4*13) mod 17 = 109 mod 17 = 7
 *
 * n_elems = 4
 * sum_X   = 10+6+15+7 = 38 = 0x26
 * X[0]    = 10 = 0x0A
 *
 * g_result = (n_elems << 16) | (sum_X << 8) | X[0] = 0x0004260A
 */
#include <stdint.h>

volatile uint32_t g_result;

#define NTT_P  17
#define NTT_N  4
#define NTT_W  13   /* primitive 4th root of unity mod 17 */

static int ntt_a[NTT_N];
static int ntt_X[NTT_N];

/* Fast modular exponentiation: base^exp mod mod */
static int ntt_pow(int base, int exp, int mod)
{
    int result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (int)((long long)result * base % mod);
        base = (int)((long long)base * base % mod);
        exp >>= 1;
    }
    return result;
}

/* Naive O(n²) NTT over Z/p */
static void ntt_compute(void)
{
    for (int k = 0; k < NTT_N; k++) {
        int sum = 0;
        for (int j = 0; j < NTT_N; j++) {
            sum = (int)((sum + (long long)ntt_a[j] * ntt_pow(NTT_W, k * j, NTT_P)) % NTT_P);
        }
        ntt_X[k] = sum;
    }
}

void test_ntt(void)
{
    ntt_a[0] = 1; ntt_a[1] = 2; ntt_a[2] = 3; ntt_a[3] = 4;

    ntt_compute();

    /* X = [10, 6, 15, 7] */
    int sum_X = 0;
    for (int k = 0; k < NTT_N; k++) sum_X += ntt_X[k];

    g_result = ((uint32_t)NTT_N      << 16)
             | ((uint32_t)sum_X      << 8)
             | ((uint32_t)ntt_X[0]  & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_ntt();
    for (;;);
}
