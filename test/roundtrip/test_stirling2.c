/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Stirling Numbers of the Second Kind fixture.
 *
 * S(n,k) = number of ways to partition n items into k non-empty subsets.
 * Recurrence: S(n,k) = k*S(n-1,k) + S(n-1,k-1)
 * Base cases: S(0,0)=1; S(n,0)=0 for n>0; S(0,k)=0 for k>0
 *
 * Distinctive decompiler idioms:
 *   1. `st[n][k] = k * st[n-1][k] + st[n-1][k-1]` — main recurrence
 *   2. `st[0][0] = 1` — origin initialization
 *   3. `sum/xor accumulate across test cases`
 *
 * Test cases:
 *   S(4,2)=7, S(5,3)=25, S(6,3)=90
 *   sum=122=0x7A, xor=7^25^90=68=0x44
 *
 * g_result = (3 << 16) | (122 << 8) | 68 = 0x00037A44
 */
#include <stdint.h>

volatile uint32_t g_result;

#define ST_N 7
#define ST_K 5

static uint32_t st[ST_N][ST_K];

void test_stirling2(void)
{
    for (int n = 0; n < ST_N; n++)
        for (int k = 0; k < ST_K; k++)
            st[n][k] = 0;
    st[0][0] = 1;
    for (int n = 1; n < ST_N; n++)
        for (int k = 1; k < ST_K; k++)
            st[n][k] = (uint32_t)k * st[n-1][k] + st[n-1][k-1];

    uint32_t a = st[4][2]; /* 7  */
    uint32_t b = st[5][3]; /* 25 */
    uint32_t c = st[6][3]; /* 90 */

    g_result = (3u << 16) | (((a + b + c) & 0xFFu) << 8) | ((a ^ b ^ c) & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_stirling2();
    for (;;);
}
