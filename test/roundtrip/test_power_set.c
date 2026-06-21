/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Power Set Enumeration (bitmask) fixture.
 *
 * Enumerates all 2^n subsets of {1,2,3,4} using bitmask iteration.
 * Tracks total subsets, sum of all subset sizes, and sum of all elements
 * across all subsets.
 *
 * Distinctive decompiler idioms:
 *   1. `for(mask=0; mask<(1<<n); mask++)` — iterate all subsets
 *   2. `for(i=0; i<n; i++) if(mask & (1<<i)) process(elems[i])` — enumerate
 *   3. `sum_sizes = n * 2^(n-1)` — each element appears in half the subsets
 *
 * n=4, total=16 subsets, sum_sizes=32, elem_sum=80 (each of {1,2,3,4}*8)
 *
 * g_result = (total<<16) | ((sum_sizes&0xFF)<<8) | (elem_sum&0xFF) = 0x00102050
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_power_set(void)
{
    static const int elems[4] = {1, 2, 3, 4};
    int n = 4;
    uint32_t total     = 0;
    uint32_t sum_sizes = 0;
    uint32_t elem_sum  = 0;

    for (int mask = 0; mask < (1 << n); mask++) {
        total++;
        for (int i = 0; i < n; i++) {
            if (mask & (1 << i)) {
                sum_sizes++;
                elem_sum += (uint32_t)elems[i];
            }
        }
    }
    /* total=16=0x10, sum_sizes=32=0x20, elem_sum=80=0x50 */
    g_result = (total << 16) | ((sum_sizes & 0xFFu) << 8) | (elem_sum & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_power_set();
    for (;;);
}
