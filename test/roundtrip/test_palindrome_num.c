/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Palindrome Number Detection fixture.
 *
 * Checks if an integer is a palindrome by reversing digits.
 * Negative numbers and numbers ending in 0 (except 0) are non-palindromes.
 *
 * Distinctive decompiler idioms:
 *   1. `if(n<0) return 0` — negatives are not palindromes
 *   2. `while(n>0){rev=rev*10+n%10;n/=10;}` — digit reversal
 *   3. `return orig==rev` — palindrome iff reversal equals original
 *
 * Test numbers: {121,-121,10,0,12321,11}
 * Palindromes: 121→1, -121→0, 10→0, 0→1, 12321→1, 11→1 → count=4
 * XOR of palindromic values: 121^0^12321^11 = 12371 (0x3053) → low byte=0x53
 *
 * g_result = (n<<16)|(count<<8)|(xor&0xFF) = 0x00060453
 */
#include <stdint.h>

volatile uint32_t g_result;

static int is_pal_num(int n)
{
    if (n < 0) return 0;
    long rev = 0, orig = n;
    while (n > 0) { rev = rev * 10 + n % 10; n /= 10; }
    return (long)orig == rev;
}

void test_palindrome_num(void)
{
    static const int nums[6] = {121, -121, 10, 0, 12321, 11};
    int count = 0;
    uint32_t xr = 0;

    for (int i = 0; i < 6; i++) {
        if (is_pal_num(nums[i])) {
            count++;
            xr ^= (uint32_t)nums[i];
        }
    }
    /* count=4, xr=121^0^12321^11=12371=0x3053, low byte=0x53 */
    g_result = (6u << 16)
             | ((uint32_t)count << 8)
             | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_palindrome_num();
    for (;;);
}
