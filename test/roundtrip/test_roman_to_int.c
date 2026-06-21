/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Roman Numeral to Integer fixture.
 *
 * Converts Roman numerals to integers using the subtraction rule:
 * scan left to right; if current < next, subtract; else add.
 *
 * Distinctive decompiler idioms:
 *   1. `if (val[s[i]] < val[s[i+1]]) result -= val[s[i]]`
 *   2. `else result += val[s[i]]`
 *   3. `result += val[s[last]]` — always add the last symbol
 *
 * Test cases (4 strings):
 *   "III"     → 3
 *   "IX"      → 9
 *   "XLII"    → 42
 *   "MCMXCIX" → 1999
 *   sum=2053, sum%256=5, xor=2031, xor%256=239
 *
 * g_result = (4 << 16) | (5 << 8) | 239 = 0x000405EF
 */
#include <stdint.h>

volatile uint32_t g_result;

static int rval(char c)
{
    switch (c) {
    case 'I': return 1;
    case 'V': return 5;
    case 'X': return 10;
    case 'L': return 50;
    case 'C': return 100;
    case 'D': return 500;
    case 'M': return 1000;
    default:  return 0;
    }
}

static int roman_to_int(const char *s, int n)
{
    int result = 0;
    for (int i = 0; i < n - 1; i++) {
        if (rval(s[i]) < rval(s[i+1]))
            result -= rval(s[i]);
        else
            result += rval(s[i]);
    }
    result += rval(s[n-1]);
    return result;
}

void test_roman_to_int(void)
{
    int r0 = roman_to_int("III",     3); /* 3    */
    int r1 = roman_to_int("IX",      2); /* 9    */
    int r2 = roman_to_int("XLII",    4); /* 42   */
    int r3 = roman_to_int("MCMXCIX", 7); /* 1999 */

    uint32_t sum = (uint32_t)(r0 + r1 + r2 + r3); /* 2053 */
    uint32_t xr  = (uint32_t)(r0 ^ r1 ^ r2 ^ r3); /* 2031 */

    g_result = (4u << 16) | ((sum & 0xFFu) << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_roman_to_int();
    for (;;);
}
