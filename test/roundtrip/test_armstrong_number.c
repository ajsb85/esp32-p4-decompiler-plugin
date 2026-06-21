/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Armstrong (Narcissistic) Number fixture.
 *
 * An Armstrong number of d digits satisfies: n == sum(digit^d for each digit).
 * Examples: 1,2,...,9 (1-digit), 153=1^3+5^3+3^3, 370, 371, 407 (3-digit).
 *
 * Distinctive decompiler idioms:
 *   1. Digit count loop: `while (tmp /= 10) digits++`
 *   2. Power-of-digit accumulation: `d = n%10; n/=10; sum += pow_d(d,digits)`
 *   3. Integer exponentiation inner loop: `for(i=0;i<exp;i++) result*=base`
 *   4. Self-match test: `sum == original_n`
 *   5. Collection XOR fold: xor all Armstrong numbers found in range
 *
 * Test: collect 3-digit Armstrong numbers in [100..500]
 *   153=1^3+5^3+3^3=1+125+27=153 ✓
 *   370=3^3+7^3+0^3=27+343+0=370 ✓
 *   371=3^3+7^3+1^3=27+343+1=371 ✓
 *   407=4^3+0^3+7^3=64+0+343=407 ✓
 *   So in [100..500]: 153, 370, 371, 407 → count=4
 *   XOR: 153^370^371^407 = 0x010F = 271 (low byte = 0x0F = 15)
 *   checksum = (4 + 15) & 0xFF = 19 = 0x13
 *   g_result = (4<<16)|(15<<8)|19 = 0x040F13
 */
#include <stdint.h>

volatile uint32_t g_result;

#define ARM_LO  100u
#define ARM_HI  500u

static uint32_t uint_pow(uint32_t base, uint32_t exp)
{
    uint32_t result = 1u;
    for (uint32_t i = 0u; i < exp; i++)
        result *= base;
    return result;
}

static uint32_t count_digits(uint32_t n)
{
    uint32_t d = 0u;
    uint32_t tmp = n;
    do {
        d++;
        tmp /= 10u;
    } while (tmp > 0u);
    return d;
}

static int32_t is_armstrong(uint32_t n)
{
    uint32_t digits = count_digits(n);
    uint32_t sum    = 0u;
    uint32_t tmp    = n;
    while (tmp > 0u) {
        uint32_t d = tmp % 10u;
        tmp /= 10u;
        sum += uint_pow(d, digits);
    }
    return (sum == n) ? 1 : 0;
}

void test_armstrong_number(void)
{
    uint32_t arm_count = 0u;
    uint32_t xor_arm   = 0u;

    for (uint32_t i = ARM_LO; i <= ARM_HI; i++) {
        if (is_armstrong(i)) {
            arm_count++;
            xor_arm ^= i;
        }
    }

    uint32_t xor_low  = xor_arm & 0xFFu;
    uint32_t checksum = (arm_count + xor_low) & 0xFFu;
    g_result = (arm_count << 16) | (xor_low << 8) | checksum;
}

__attribute__((noreturn)) void _start(void)
{
    test_armstrong_number();
    for (;;);
}
