/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Sum over Subsets (SOS) DP fixture.
 *
 * Computes for each mask: f[mask] = sum of a[sub] for all sub ⊆ mask.
 * Classic bitmask DP:
 *   for each bit i: for each mask with bit i set: f[mask] += f[mask ^ (1<<i)]
 *
 * Distinctive decompiler idioms:
 *   1. `for i in 0..n-1: for mask: if mask&(1<<i): f[mask]+=f[mask^(1<<i)]`
 *   2. `f[mask] = a[mask]` initialization
 *   3. `f[ALL_BITS]` = sum of all elements
 *
 * Input (n=3 bits, 8 subsets): a={3,1,4,1,5,9,2,6}
 * After SOS:
 *   f[7]=31 (all elements), f[5]=18 (sub={0b001,0b100,0b101}+{0b000}=3+1+5+9),
 *   f[6]=14 (sub={0b010,0b100,0b110}+{0b000}=3+4+5+2)
 *   sum=31+18+14=63=0x3F, xor=31^18^14=3=0x03
 *
 * g_result = (3 << 16) | (63 << 8) | 3 = 0x00033F03
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SOS_N 3
#define SOS_M 8

static uint32_t sos_f[SOS_M];
static const uint32_t sos_a[SOS_M] = {3, 1, 4, 1, 5, 9, 2, 6};

void test_sos_dp(void)
{
    for (int m = 0; m < SOS_M; m++) sos_f[m] = sos_a[m];
    for (int i = 0; i < SOS_N; i++)
        for (int mask = 0; mask < SOS_M; mask++)
            if (mask & (1 << i))
                sos_f[mask] += sos_f[mask ^ (1 << i)];

    uint32_t f7 = sos_f[7]; /* 31 */
    uint32_t f5 = sos_f[5]; /* 18 */
    uint32_t f6 = sos_f[6]; /* 14 */

    g_result = (3u << 16)
             | (((f7 + f5 + f6) & 0xFFu) << 8)
             | ((f7 ^ f5 ^ f6) & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_sos_dp();
    for (;;);
}
