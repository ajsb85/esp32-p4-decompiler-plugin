/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Pascal's triangle mod p fixture.
 *
 * Lucas's theorem: C(n, k) mod p (prime p) != 0  iff  for every digit
 * position in base p, the digit of k is <= the digit of n.
 *
 * This fixture counts entries in the first N=20 rows of Pascal's triangle
 * (rows 0..19, so n in [0,19]) that are NOT divisible by p=3.
 *
 * For each (n, k) with 0 <= k <= n, apply Lucas: repeatedly check
 * that (k % p) <= (n % p), then advance n,k by dividing by p.
 *
 * Also compute: XOR of (n XOR k) for all non-zero-mod-p entries,
 * taken mod 256.
 *
 * Results (verified by Python):
 *   N = 20, p = 3
 *   count_nonzero = 117 = 0x75
 *   xor_nk        = 26  = 0x1A
 *
 * g_result = (20<<16)|(117<<8)|26 = 0x0014751A
 * Bytes: 0x14=20, 0x75=117, 0x1A=26 — all distinct and non-zero.
 *
 * Distinctive decompiler idioms:
 *   1. Lucas check loop: while (k > 0) { if (k%p > n%p) return 0; n/=p; k/=p; }
 *   2. Double loop over triangle entries: for n in 0..N-1, k in 0..n
 *   3. XOR accumulation with (n^k) only for non-zero mod-p entries
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PT_N 20u
#define PT_P 3u

/* Returns 1 if C(n,k) mod PT_P != 0, using Lucas's theorem. */
static int lucas_nonzero(uint32_t n, uint32_t k)
{
    while (k > 0u) {
        if ((k % PT_P) > (n % PT_P)) {
            return 0;
        }
        n /= PT_P;
        k /= PT_P;
    }
    return 1;
}

void test_pascal_triangle_mod(void)
{
    uint32_t count_nonzero = 0u;
    uint32_t xor_nk        = 0u;
    uint32_t n, k;

    for (n = 0u; n < PT_N; n++) {
        for (k = 0u; k <= n; k++) {
            if (lucas_nonzero(n, k)) {
                count_nonzero++;
                xor_nk ^= ((n ^ k) & 0xFFu);
            }
        }
    }

    /* count_nonzero=117=0x75, xor_nk=26=0x1A
     * g_result = (20<<16)|(117<<8)|26 = 0x0014751A */
    g_result = (PT_N << 16) | (count_nonzero << 8) | (xor_nk & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_pascal_triangle_mod();
    for (;;);
}
