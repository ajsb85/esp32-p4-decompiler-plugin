/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Tribonacci sequence fixture.
 *
 * Tribonacci: T(n) = T(n-1) + T(n-2) + T(n-3), with T(0)=0, T(1)=1, T(2)=1.
 * Computes T(0)..T(9) then accumulates sum and XOR over all values.
 *
 * Distinctive decompiler idioms:
 *   1. `t[i] = t[i-1] + t[i-2] + t[i-3]` — 3-term linear recurrence
 *   2. Seed initialisation: t[0]=0, t[1]=1, t[2]=1 (offset from Fibonacci)
 *   3. Accumulate sum and XOR in same pass over result array
 *
 * Sequence: 0, 1, 1, 2, 4, 7, 13, 24, 44, 81
 *
 * n          = 10
 * sum        = 177  (0xB1)
 * xor_all    = 105  (0x69)
 *
 * g_result = (n << 16) | (sum << 8) | xor_all = 0x000AB169
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TRIB_N 10

static uint32_t trib_vals[TRIB_N];

void test_tribonacci(void)
{
    trib_vals[0] = 0;
    trib_vals[1] = 1;
    trib_vals[2] = 1;
    for (int i = 3; i < TRIB_N; i++)
        trib_vals[i] = trib_vals[i-1] + trib_vals[i-2] + trib_vals[i-3];

    uint32_t trib_sum = 0, trib_xor = 0;
    for (int i = 0; i < TRIB_N; i++) {
        trib_sum += trib_vals[i];
        trib_xor ^= trib_vals[i];
    }

    g_result = ((uint32_t)TRIB_N << 16) | ((trib_sum & 0xFFu) << 8) | (trib_xor & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_tribonacci();
    for (;;);
}
