/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Palindrome Prime fixture.
 *
 * A palindrome prime is a number that is both prime and a palindrome
 * (reads the same forwards and backwards in decimal).
 * Examples: 2, 3, 5, 7, 11, 101, 131, 151, 181, 191...
 *
 * Distinctive decompiler idioms:
 *   1. `is_palindrome(n)`: reverse digit sequence, compare to original
 *   2. `is_prime(n)`: trial division up to sqrt(n)
 *   3. Combined filter: is_prime(n) && is_palindrome(n)
 *   4. Count and accumulate for result encoding
 *
 * Test: palindrome primes in [1..200].
 *   2,3,5,7,11,101,131,151,181,191 => 10 numbers.
 *   Last palindrome prime <= 200: 191, 191 & 0xFF = 191 = 0xBF.
 *   count = 10 = 0x0A.
 *   checksum = (10 + 191) & 0xFF = 201 & 0xFF = 201 = 0xC9.
 *   g_result = (10<<16)|(191<<8)|201 = 0x0ABFC9
 */
#include <stdint.h>

volatile uint32_t g_result;

static int32_t is_prime(uint32_t n)
{
    if (n < 2u) return 0;
    if (n == 2u) return 1;
    if ((n & 1u) == 0u) return 0;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0;
    }
    return 1;
}

static int32_t is_palindrome(uint32_t n)
{
    uint32_t original = n;
    uint32_t reversed = 0u;
    while (n > 0u) {
        reversed = reversed * 10u + (n % 10u);
        n /= 10u;
    }
    return (original == reversed) ? 1 : 0;
}

void test_palindrome_prime(void)
{
    uint32_t count = 0u;
    uint32_t last  = 0u;
    for (uint32_t i = 2u; i <= 200u; i++) {
        if (is_prime(i) && is_palindrome(i)) {
            count++;
            last = i;
        }
    }
    /* count=10, last=191 */
    uint32_t checksum = (count + last) & 0xFFu;
    g_result = (count << 16) | ((last & 0xFFu) << 8) | checksum;
}

__attribute__((noreturn)) void _start(void)
{
    test_palindrome_prime();
    for (;;);
}
