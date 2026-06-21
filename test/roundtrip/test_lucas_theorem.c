/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Lucas Theorem for C(n,k) mod prime fixture.
 *
 * Lucas theorem: C(n, k) mod p = ∏ C(n_i, k_i) mod p
 * where n_i and k_i are the base-p digits of n and k respectively.
 * Returns 0 if k_i > n_i for any i (one "forbidden" digit).
 *
 * Distinctive decompiler idioms:
 *   1. `return comb_mod_p(n%p, k%p, p) * lucas(n/p, k/p, p) % p` — recursive digit decomp
 *   2. `if (k == 0) return 1` — base case
 *   3. `comb_mod_p(n, k, p) = fact[n] * inv_fact[k] % p * inv_fact[n-k] % p` — precomputed
 *   4. Fermat's little theorem for modular inverse: `inv_fact[p-1] = mod_pow(fact[p-1], p-2, p)`
 *   5. Build fact table up to p-1 only (not n) since digits are < p
 *
 * Example: C(10, 3) mod 7
 *   10 in base 7 = [1, 3]  (10 = 1*7 + 3)
 *   3  in base 7 = [0, 3]  (3  = 0*7 + 3)
 *   Lucas: C(1,0) * C(3,3) mod 7 = 1 * 1 = 1
 *   Verify: C(10,3) = 120 = 17*7+1 ≡ 1 mod 7 ✓
 *
 * n   = 10 = 0x0A
 * p   = 7  = 0x07
 * res = 1  = 0x01
 *
 * g_result = (n << 16) | (p << 8) | res = 0x0A0701
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LT_PMAX 8   /* prime p ≤ 7, table size up to p */

static int lt_fact[LT_PMAX];
static int lt_inv_fact[LT_PMAX];

static int lt_pow(int b, int e, int m)
{
    int r = 1; b %= m;
    while (e > 0) {
        if (e & 1) r = r * b % m;
        b = b * b % m; e >>= 1;
    }
    return r;
}

static void lt_build(int p)
{
    lt_fact[0] = 1;
    for (int i = 1; i < p; i++) lt_fact[i] = lt_fact[i-1] * i % p;
    lt_inv_fact[p-1] = lt_pow(lt_fact[p-1], p - 2, p);
    for (int i = p-2; i >= 0; i--)
        lt_inv_fact[i] = lt_inv_fact[i+1] * (i + 1) % p;
}

static int lt_comb(int n, int k, int p)
{
    if (k < 0 || k > n) return 0;
    return lt_fact[n] * lt_inv_fact[k] % p * lt_inv_fact[n-k] % p;
}

static int lt_lucas(int n, int k, int p)
{
    if (k == 0) return 1;
    return lt_comb(n % p, k % p, p) * lt_lucas(n / p, k / p, p) % p;
}

void test_lucas_theorem(void)
{
    int p = 7;
    lt_build(p);
    int r = lt_lucas(10, 3, p);  /* C(10,3)=120 ≡ 1 mod 7 */

    g_result = ((uint32_t)10 << 16)
             | ((uint32_t)p  << 8)
             | ((uint32_t)r & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_lucas_theorem();
    for (;;);
}
