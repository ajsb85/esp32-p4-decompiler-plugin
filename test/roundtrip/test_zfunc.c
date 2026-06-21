/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Z-function (Z-algorithm) round-trip fixture.
 *
 * Z-function: z[i] = length of the longest string starting at position i
 * that is also a prefix of the full string.
 *
 * Classic O(n) implementation using the [l, r) window trick:
 *
 *   if (i < r) z[i] = min(r-i, z[i-l]);
 *   while (i+z[i] < n && s[z[i]] == s[i+z[i]]) z[i]++;
 *   if (i+z[i] > r) { l = i; r = i+z[i]; }
 *
 * Two decompiler-visible idioms:
 *   1. ternary min(r-i, z[i-l]) initialisation
 *   2. extend loop comparing s[z[i]] with s[i+z[i]]
 *
 * Input: "AABAAB" (n=6)
 *
 * Z-array trace:
 *   z[0] = 0  (convention: undefined, left 0)
 *   z[1] = 1  ("A" matches prefix "A")
 *   z[2] = 0  ("B" ≠ "A")
 *   z[3] = 3  ("AAB" matches prefix "AAB")
 *   z[4] = 1  ("A" matches prefix "A")
 *   z[5] = 0  ("B" ≠ "A")
 *
 *   sum_z = 0+1+0+3+1+0 = 5
 *   xor_z = 0^1^0^3^1^0 = 3
 *   n     = 6
 *
 * g_result = (n << 16) | (sum_z << 8) | xor_z = 0x00060503
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Z-function ────────────────────────────────────────────────────────────── */

#define ZFUNC_N 6

static int zf[ZFUNC_N];

static void z_function(const char *s, int n, int *z)
{
    z[0] = 0;
    int l = 0, r = 0;
    for (int i = 1; i < n; i++) {
        if (i < r)
            z[i] = (r - i < z[i - l]) ? r - i : z[i - l];
        else
            z[i] = 0;
        while (i + z[i] < n && s[z[i]] == s[i + z[i]])
            z[i]++;
        if (i + z[i] > r) {
            l = i;
            r = i + z[i];
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_zfunc(void)
{
    static const char s[ZFUNC_N + 1] = "AABAAB";

    z_function(s, ZFUNC_N, zf);   /* z = {0,1,0,3,1,0} */

    uint32_t sum_z = 0, xor_z = 0;
    for (int i = 0; i < ZFUNC_N; i++) {
        sum_z += (uint32_t)zf[i];
        xor_z ^= (uint32_t)zf[i];
    }

    g_result = ((uint32_t)ZFUNC_N << 16)
             | (sum_z << 8)
             | (xor_z & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_zfunc();
    for (;;);
}
