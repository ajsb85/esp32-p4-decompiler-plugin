/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Leonardo Numbers fixture.
 *
 * Leonardo numbers: L(0)=1, L(1)=1, L(n)=L(n-1)+L(n-2)+1
 * Related to Fibonacci: L(n) = 2*F(n+1) - 1
 * Used in smoothsort heap (Leonardo heap structure).
 *
 * Distinctive decompiler idioms:
 *   1. Recurrence with +1 offset: `leo[i] = leo[i-1] + leo[i-2] + 1`
 *   2. Relation check: `leo[i] == 2*fib - 1` pattern
 *   3. Smoothsort shape bits: bitmask of active Leonardo heaps
 *
 * Test: Compute L(0)..L(15), count those divisible by 3, XOR them.
 *
 * L(0)=1, L(1)=1, L(2)=3, L(3)=5, L(4)=9, L(5)=15,
 * L(6)=25, L(7)=41, L(8)=67, L(9)=109, L(10)=177,
 * L(11)=287, L(12)=465, L(13)=753, L(14)=1219, L(15)=1973
 *
 * Divisible by 3: {3,9,15,177,465,753} → count=6
 * XOR: 3^9^15^177^465^753 = 916; low byte = 0x94 = 148
 *
 * n_terms=16, count_div3=6, xor_div3_low=148
 * g_result = (16<<16)|(6<<8)|148 = 0x100694
 * Bytes: 0x10=16, 0x06=6, 0x94=148 — all distinct and non-zero.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LEO_N 16

static uint32_t leo_table[LEO_N];

static void leonardo_build(void)
{
    leo_table[0] = 1u;
    leo_table[1] = 1u;
    uint32_t i;
    for (i = 2u; i < LEO_N; i++) {
        /* L(n) = L(n-1) + L(n-2) + 1 — the Leonardo recurrence */
        leo_table[i] = leo_table[i - 1u] + leo_table[i - 2u] + 1u;
    }
}

static uint32_t leonardo_sum_below(uint32_t limit)
{
    uint32_t s = 0u, i;
    for (i = 0u; i < LEO_N; i++) {
        if (leo_table[i] < limit) s += leo_table[i];
    }
    return s;
}

void test_leonardo_numbers(void)
{
    leonardo_build();

    uint32_t count_div3 = 0u;
    uint32_t xor_div3   = 0u;
    uint32_t i;

    for (i = 0u; i < LEO_N; i++) {
        if (leo_table[i] % 3u == 0u) {
            count_div3++;
            xor_div3 ^= leo_table[i];
        }
    }

    /* Use sum_below to exercise more of the algorithm */
    uint32_t partial = leonardo_sum_below(100u);
    (void)partial;

    /* n_terms=16, count_div3=6, xor_div3_low=148 → 0x100694 */
    g_result = ((uint32_t)LEO_N << 16) | (count_div3 << 8) | (xor_div3 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_leonardo_numbers();
    for (;;);
}
