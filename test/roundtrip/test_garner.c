/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Garner's Algorithm (Mixed-Radix CRT) fixture.
 *
 * Garner's algorithm reconstructs an integer x from its residues r[i] modulo
 * pairwise-coprime moduli m[i], using mixed-radix representation:
 *
 *   x = a[0] + a[1]*m[0] + a[2]*m[0]*m[1] + ...
 *
 * where the mixed-radix digits a[k] are computed iteratively by:
 *   a[k] = r[k]
 *   for j = 0..k-1:
 *     a[k] = inv(m[j], m[k]) * (a[k] - a[j]) mod m[k]
 *
 * Distinctive decompiler idioms:
 *   1. Double-nested loop: outer k, inner j < k (triangular update)
 *   2. `a[k] = gar_inv(m[j], m[k]) * (a[k] - a[j]) % m[k]` — mixed-radix step
 *   3. `if (a[k] < 0) a[k] += m[k]` — normalize negative residue
 *   4. `x += a[k] * prod; prod *= m[k]` — horner-like reconstruction
 *
 * Test case: x = 89, n = 3 moduli, m = {3, 7, 11}
 *   r[0] = 89 mod 3  = 2
 *   r[1] = 89 mod 7  = 5
 *   r[2] = 89 mod 11 = 1
 *
 *   Mixed-radix digits:
 *   a[0] = 2
 *   a[1] = inv(3,7) * (5-2) mod 7 = 5*3 mod 7 = 1
 *   a[2] = (inv(3,11) * (1-2) - a[1]) * inv(7,11) mod 11 = 4
 *   x = 2 + 1*3 + 4*21 = 2 + 3 + 84 = 89 ✓
 *
 * n_moduli     = 3
 * x_val        = 89 = 0x59
 * sum_residues = 2+5+1 = 8
 *
 * g_result = (n_moduli << 16) | (x_val << 8) | sum_residues = 0x00035908
 */
#include <stdint.h>

volatile uint32_t g_result;

#define GAR_N 3

/* Modular inverse of a mod m via extended Euclidean algorithm */
static int gar_inv(int a, int m)
{
    int old_r = a, r = m, old_s = 1, s = 0;
    while (r != 0) {
        int q = old_r / r;
        int tmp;
        tmp = r;   r   = old_r - q * r;   old_r = tmp;
        tmp = s;   s   = old_s - q * s;   old_s = tmp;
    }
    return ((old_s % m) + m) % m;
}

/* Garner's mixed-radix CRT reconstruction */
static int garner_reconstruct(const int *r, const int *m, int n)
{
    int a[GAR_N];
    for (int k = 0; k < n; k++) {
        a[k] = r[k];
        for (int j = 0; j < k; j++) {
            a[k] = gar_inv(m[j], m[k]) * ((a[k] - a[j]) % m[k]) % m[k];
            if (a[k] < 0) a[k] += m[k];
        }
    }
    int x = 0, prod = 1;
    for (int k = 0; k < n; k++) {
        x += a[k] * prod;
        prod *= m[k];
    }
    return x;
}

void test_garner(void)
{
    static const int m[GAR_N] = {3, 7, 11};
    static const int r[GAR_N] = {2, 5, 1};  /* 89 mod {3,7,11} */

    int x = garner_reconstruct(r, m, GAR_N);  /* 89 */
    int sum_r = r[0] + r[1] + r[2];            /* 8  */

    g_result = ((uint32_t)GAR_N << 16)
             | ((uint32_t)x     << 8)
             | ((uint32_t)sum_r & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_garner();
    for (;;);
}
