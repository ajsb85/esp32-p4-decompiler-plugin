/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Lucas Numbers sequence fixture.
 *
 * Lucas sequence: L(0)=2, L(1)=1, L(n)=L(n-1)+L(n-2)
 * Related to Fibonacci but with different seed values.
 *
 * Distinctive decompiler idioms:
 *   1. `L[0]=2; L[1]=1` — non-standard initial conditions
 *   2. `for(i=2;i<n;i++) L[i]=L[i-1]+L[i-2]` — same recurrence as Fibonacci
 *   3. Sum of first 6 terms and L[10] as result metrics
 *
 * Sequence: 2,1,3,4,7,11,18,29,47,76,123,199,...
 * n_terms=6, sum[0..5]=28=0x1C, L[10]=123=0x7B
 *
 * g_result = (6<<16)|(L[10]%256<<8)|(sum_6&0xFF) = 0x00067B1C
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_lucas_numbers(void)
{
    int L[12];
    L[0] = 2; L[1] = 1;
    for (int i = 2; i < 12; i++) L[i] = L[i-1] + L[i-2];

    int sum = 0;
    for (int i = 0; i < 6; i++) sum += L[i];
    /* sum=2+1+3+4+7+11=28=0x1C, L[10]=123=0x7B */
    g_result = (6u << 16)
             | (((uint32_t)L[10] & 0xFFu) << 8)
             | ((uint32_t)sum & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_lucas_numbers();
    for (;;);
}
