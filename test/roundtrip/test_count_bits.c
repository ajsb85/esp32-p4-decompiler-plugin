/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Count set bits (Brian Kernighan) fixture.
 *
 * Counts set bits in each integer 0..N-1 using the Brian Kernighan trick
 * (x &= x-1 clears the lowest set bit), then accumulates total and XOR.
 *
 * Distinctive decompiler idioms:
 *   1. `while (x) { x &= x - 1; count++; }` — Brian Kernighan bit count
 *   2. `for (i = 0; i < n; i++) total += popcount(i)` — range accumulation
 *   3. `xor ^= count` — XOR accumulation of per-element counts
 *
 * Range: 0..15 (N=16)
 * Per-count: 0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4
 *
 * n          = 16
 * total_bits = 32
 * xor_counts = 4
 *
 * g_result = (n << 16) | (total_bits << 8) | xor_counts = 0x00102004
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CB_N 16

static int cb_popcount(unsigned int x)
{
    int count = 0;
    while (x) { x &= x - 1u; count++; }
    return count;
}

void test_count_bits(void)
{
    uint32_t total = 0, xor_counts = 0;
    for (int i = 0; i < CB_N; i++) {
        int c = cb_popcount((unsigned int)i);
        total += (uint32_t)c;
        xor_counts ^= (uint32_t)c;
    }

    g_result = ((uint32_t)CB_N << 16) | ((total & 0xFFu) << 8) | (xor_counts & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_count_bits();
    for (;;);
}
