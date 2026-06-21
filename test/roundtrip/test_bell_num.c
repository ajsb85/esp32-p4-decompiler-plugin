/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Bell Numbers (partition counting) fixture.
 *
 * Bell number B(n) counts the number of partitions of a set of n elements.
 * Computed using the Bell triangle: B(0)=1, then each row starts with the
 * last element of the previous row, and subsequent elements are the sum
 * of the previous element and the element above it.
 *
 * Distinctive decompiler idioms:
 *   1. `bell[i][0] = bell[i-1][i-1]` — start of new row
 *   2. `bell[i][j] = bell[i][j-1] + bell[i-1][j-1]` — recurrence
 *   3. `return bell[n][0]` — diagonal extract
 *
 * Test cases:
 *   B(3)=5, B(4)=15, B(5)=52
 *   sum=72=0x48, xor=5^15^52=62=0x3E
 *
 * g_result = (3 << 16) | (72 << 8) | 62 = 0x0003483E
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BN_MAX 6

static uint32_t bn_bell[BN_MAX][BN_MAX];

static uint32_t bell_number(int n)
{
    bn_bell[0][0] = 1;
    for (int i = 1; i <= n; i++) {
        bn_bell[i][0] = bn_bell[i-1][i-1];
        for (int j = 1; j <= i; j++)
            bn_bell[i][j] = bn_bell[i][j-1] + bn_bell[i-1][j-1];
    }
    return bn_bell[n][0];
}

void test_bell_num(void)
{
    uint32_t b3 = bell_number(3); /* 5  */
    uint32_t b4 = bell_number(4); /* 15 */
    uint32_t b5 = bell_number(5); /* 52 */

    g_result = (3u << 16)
             | (((b3 + b4 + b5) & 0xFFu) << 8)
             | ((b3 ^ b4 ^ b5) & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_bell_num();
    for (;;);
}
