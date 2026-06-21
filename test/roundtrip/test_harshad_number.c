/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Harshad (Niven) Number fixture.
 *
 * A Harshad number is a positive integer divisible by the sum of its digits.
 * e.g., 18 is Harshad because 1+8=9 and 18%9==0.
 *
 * Distinctive decompiler idioms:
 *   1. `s = digit_sum(n)` — repeated mod-10 digit extraction
 *   2. `if (n % s == 0)` — divisibility by digit sum
 *   3. Loop counting Harshad numbers up to bound
 *   4. Encoding: (n_harshad_found << 16) | (last_harshad_low8 << 8) | checksum
 *
 * Test: count Harshad numbers in [1..50].
 *   Harshad numbers in [1..50]: 1,2,3,4,5,6,7,8,9,10,12,18,20,21,24,27,30,
 *                                36,40,42,45,48,50 => 23 numbers.
 *   Last Harshad <= 50: 50, 50 & 0xFF = 50 = 0x32.
 *   Checksum = (23 + 50) & 0xFF = 73 & 0xFF = 73 = 0x49.
 *   g_result = (23<<16)|(50<<8)|73 = 0x173249
 */
#include <stdint.h>

volatile uint32_t g_result;

static uint32_t digit_sum(uint32_t n)
{
    uint32_t s = 0;
    while (n > 0) {
        s += n % 10u;
        n /= 10u;
    }
    return s;
}

static int32_t is_harshad(uint32_t n)
{
    uint32_t s = digit_sum(n);
    if (s == 0u) return 0;
    return (n % s == 0u) ? 1 : 0;
}

void test_harshad_number(void)
{
    uint32_t count = 0;
    uint32_t last  = 0;
    for (uint32_t i = 1u; i <= 50u; i++) {
        if (is_harshad(i)) {
            count++;
            last = i;
        }
    }
    /* count=23, last=50 */
    uint32_t checksum = (count + last) & 0xFFu;
    g_result = (count << 16) | ((last & 0xFFu) << 8) | checksum;
}

__attribute__((noreturn)) void _start(void)
{
    test_harshad_number();
    for (;;);
}
