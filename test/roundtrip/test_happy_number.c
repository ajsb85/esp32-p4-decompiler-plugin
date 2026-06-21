/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Happy Number fixture.
 *
 * A happy number is defined by: repeatedly replace n with the sum of squares
 * of its digits; if the process terminates at 1 the number is happy.
 * Unhappy numbers cycle through a fixed set never reaching 1.
 *
 * Distinctive decompiler idioms:
 *   1. Digit extraction loop: `d = n % 10; n /= 10; sum += d*d`
 *   2. Cycle detection: compare against known unhappy cycle anchor 4
 *      (once sum reaches 4 it cycles forever through 4->16->37->58->89->145->42->20->4)
 *   3. Happy check: `while (n != 1 && n != 4)` termination
 *   4. Count accumulation: iterate over range, classify each number
 *   5. Result fold: pack count and XOR into g_result
 *
 * Test: count happy numbers in [1..20]
 *   Happy: 1,7,10,13,19 → count = 5
 *   XOR of happy numbers: 1^7^10^13^19 = 0x12 = 18
 *   checksum = (5 + 18) & 0xFF = 23 = 0x17
 *   g_result = (5<<16)|(18<<8)|23 = 0x051217
 */
#include <stdint.h>

volatile uint32_t g_result;

#define HN_LO  1
#define HN_HI  20

static uint32_t digit_sum_sq(uint32_t n)
{
    uint32_t s = 0u;
    while (n > 0u) {
        uint32_t d = n % 10u;
        n /= 10u;
        s += d * d;
    }
    return s;
}

static int32_t is_happy(uint32_t n)
{
    while (n != 1u && n != 4u)
        n = digit_sum_sq(n);
    return (n == 1u) ? 1 : 0;
}

void test_happy_number(void)
{
    uint32_t hn_count = 0u;
    uint32_t xor_happy = 0u;

    for (uint32_t i = HN_LO; i <= HN_HI; i++) {
        if (is_happy(i)) {
            hn_count++;
            xor_happy ^= i;
        }
    }

    uint32_t checksum = (hn_count + xor_happy) & 0xFFu;
    g_result = (hn_count << 16) | (xor_happy << 8) | checksum;
}

__attribute__((noreturn)) void _start(void)
{
    test_happy_number();
    for (;;);
}
