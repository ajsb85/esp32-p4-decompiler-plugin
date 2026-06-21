/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Catalan Numbers DP fixture.
 *
 * The nth Catalan number counts: BSTs with n+1 leaves, valid parenthesizations,
 * triangulations of (n+2)-gon, etc.
 *
 * Recurrence:
 *   C(0) = 1
 *   C(n) = sum_{i=0}^{n-1} C(i) * C(n-1-i)
 *
 * Distinctive decompiler idioms:
 *   1. Inner product loop: for (i=0; i<n; i++) cat[n] += cat[i] * cat[n-1-i]
 *   2. Accumulate into cat[n] using all prior values (quadratic fill)
 *   3. Index complement: cat[n-1-i] (mirrors product)
 *
 * Values:
 *   C(0)=1  C(1)=1  C(2)=2  C(3)=5  C(4)=14  C(5)=42
 *
 * Queries: C(3), C(4), C(5)
 *   sum = 5+14+42 = 61  (0x3D)
 *   xor = 5^14^42 = 5^14=11, 11^42=33  (0x21)
 *
 * n_vals    = 6  (C(0)..C(5) computed)
 * sum_query = 61
 * xor_query = 33
 *
 * g_result = (n_vals << 16) | (sum_query << 8) | xor_query = 0x00063D21
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Catalan Numbers ──────────────────────────────────────────────────────── */

#define CAT_N 6

static int cat[CAT_N];

static void catalan(int n)
{
    cat[0] = 1;
    for (int k = 1; k < n; k++) {
        cat[k] = 0;
        for (int i = 0; i < k; i++)
            cat[k] += cat[i] * cat[k - 1 - i];
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_catalan(void)
{
    catalan(CAT_N);
    /* cat = {1,1,2,5,14,42} */

    uint32_t sum_q = 0, xor_q = 0;
    for (int i = 3; i <= 5; i++) {
        sum_q += (uint32_t)cat[i];
        xor_q ^= (uint32_t)cat[i];
    }
    /* sum=61, xor=33 */

    g_result = ((uint32_t)CAT_N << 16) | (sum_q << 8) | (xor_q & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_catalan();
    for (;;);
}
