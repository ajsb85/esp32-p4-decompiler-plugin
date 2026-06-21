/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Sierpinski triangle (Pascal mod 2) fixture.
 *
 * The Sierpinski triangle arises from Pascal's triangle modulo 2:
 * entry C(n, k) mod 2 == 1 iff (k & n) == k  (Lucas' theorem for p=2).
 *
 * Equivalently, C(n, k) is odd if and only if every bit of k is also set in n
 * (k is a bitwise sub-mask of n).
 *
 * This gives a fractal pattern: row n has exactly 2^popcount(n) odd entries.
 *
 * Distinctive decompiler idioms:
 *   1. Lucas mod-2 test: `if ((k & n) == k)` inside nested loop
 *   2. Popcount application: total odd entries = sum of 2^popcount(n)
 *   3. XOR accumulation over column indices k of odd entries
 *
 * Test: For rows n = 0..14, count pairs (n,k) with 0<=k<=n where C(n,k) is odd,
 *       and XOR-accumulate all k values from those pairs.
 *
 * Expected:
 *   total_odd = 65 = 0x41
 *   xor_k     = 15 = 0x0f
 *
 * g_result = (14<<16)|(65<<8)|15 = 0x000e410f
 * Bytes: 0x0e=14, 0x41=65, 0x0f=15 — all distinct and non-zero.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SIER_N 14u   /* check rows 0 .. SIER_N inclusive */

void test_sierpinski_triangle(void)
{
    uint32_t total_odd = 0u;   /* count of odd Pascal entries */
    uint32_t xor_k     = 0u;   /* XOR of column indices k of odd entries */

    uint32_t n, k;
    for (n = 0u; n <= SIER_N; n++) {
        for (k = 0u; k <= n; k++) {
            /* Lucas theorem (p=2): C(n,k) is odd iff k is a sub-mask of n */
            if ((k & n) == k) {
                total_odd++;
                xor_k ^= k;
            }
        }
    }

    /* total_odd=65=0x41, xor_k=15=0x0f
     * g_result = (14<<16)|(65<<8)|15 = 0x000e410f
     * Bytes: 0x0e, 0x41, 0x0f — distinct and non-zero */
    g_result = (SIER_N << 16) | (total_odd << 8) | (xor_k & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_sierpinski_triangle();
    for (;;);
}
