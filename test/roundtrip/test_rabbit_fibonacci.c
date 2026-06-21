/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Rabbit/Fibonacci sequence fixture.
 *
 * The "rabbit Fibonacci" sequence models Fibonacci's original rabbit problem:
 * start with 1 pair, each month new pairs reproduce. This gives the standard
 * Fibonacci sequence: 1, 1, 2, 3, 5, 8, 13, 21, ...
 *
 * We generate F(0)..F(29) (30 terms), count how many are even, and XOR
 * the low bytes of all even-indexed (0-based) terms.
 *
 * Distinct idioms:
 *   1. Classic two-variable recurrence: a=b; b=prev_a+b
 *   2. Array fill: seq[i] = seq[i-1] + seq[i-2]
 *   3. Even detection: (seq[i] & 1) == 0
 *   4. Even-index XOR harvest: for (i=0; i<N; i+=2) xor ^= (seq[i] & 0xFF)
 *
 * F(0..29): 1,1,2,3,5,8,13,21,34,55,89,144,233,377,610,987,1597,2584,
 *           4181,6765,10946,17711,28657,46368,75025,121393,196418,317811,
 *           514229,832040
 *
 * Even values: F(3k) for k>=1: F(2)=2, F(5)=8, F(8)=34, F(11)=144,
 *   F(14)=610, F(17)=2584, F(20)=10946, F(23)=46368, F(26)=196418,
 *   F(29)=832040  => 10 even values.
 *
 * XOR of even-indexed terms (i=0,2,4,...,28) low bytes:
 *   F(0)=1, F(2)=2, F(4)=5, F(6)=13, F(8)=34, F(10)=89,
 *   F(12)=233, F(14)=610->0x62, F(16)=1597->0x3D, F(18)=4181->0x55,
 *   F(20)=10946->0xA2, F(22)=28657->0x31, F(24)=75025->0x51,
 *   F(26)=196418->0x02, F(28)=514229->0x75
 *   XOR = 1^2^5^13^34^89^233^0x62^0x3D^0x55^0xA2^0x31^0x51^0x02^0x75 = 0x46 = 70
 *
 * n_tests = 30 = 0x1E
 * count_even = 10 = 0x0A
 * xor_even_idx = 70 = 0x46
 *
 * g_result = (30<<16)|(10<<8)|70 = 0x001E0A46
 * Bytes: 0x1E, 0x0A, 0x46 — all distinct and non-zero.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define RF_N 30u

void test_rabbit_fibonacci(void)
{
    uint32_t seq[RF_N];
    seq[0] = 1u;
    seq[1] = 1u;
    uint32_t i;
    for (i = 2u; i < RF_N; i++) {
        seq[i] = seq[i - 1u] + seq[i - 2u];
    }

    uint32_t count_even = 0u;
    uint32_t xor_even_idx = 0u;

    for (i = 0u; i < RF_N; i++) {
        if ((seq[i] & 1u) == 0u) {
            count_even++;
        }
        if ((i & 1u) == 0u) {
            xor_even_idx ^= (seq[i] & 0xFFu);
        }
    }

    /* count_even=10=0x0A, xor_even_idx=70=0x46
     * g_result = (30<<16)|(10<<8)|70 = 0x001E0A46 */
    g_result = (RF_N << 16) | (count_even << 8) | (xor_even_idx & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_rabbit_fibonacci();
    for (;;);
}
