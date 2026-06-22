/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Leyland Numbers fixture.
 *
 * Leyland number: x^y + y^x for integers x >= y >= 2.
 * Enumerate all (x,y) pairs with 2 <= y <= x <= 5:
 *   (2,2)=8, (3,2)=17, (3,3)=54, (4,2)=32, (4,3)=145,
 *   (4,4)=512, (5,2)=57, (5,3)=368, (5,4)=1649, (5,5)=6250
 *
 * Distinctive decompiler idioms:
 *   1. Nested loop `for x in [2..5]: for y in [2..x]`
 *   2. `pow_u32(x,y) + pow_u32(y,x)` — Leyland formula
 *   3. Trial-division primality on each Leyland value to count primes
 *
 * Results: 10 values, 1 prime (17), sum=9092, sum%251=56
 *
 * n_tests   = 10  = 0x0A
 * metric_a  =  1  = 0x01  (prime count among the 10 values)
 * metric_b  = 56  = 0x38  (sum of 10 values % 251)
 *
 * g_result = (10<<16)|(1<<8)|56 = 0x000A0138
 */
#include <stdint.h>

volatile uint32_t g_result;

static uint32_t pow_u32(uint32_t base, uint32_t exp)
{
    uint32_t result = 1u;
    uint32_t i;
    for (i = 0; i < exp; i++)
        result *= base;
    return result;
}

static uint32_t leyland_is_prime(uint32_t n)
{
    if (n < 2u) return 0;
    if (n == 2u) return 1;
    if ((n & 1u) == 0) return 0;
    uint32_t i;
    for (i = 3u; i * i <= n; i += 2u) {
        if (n % i == 0u) return 0;
    }
    return 1;
}

void test_leyland_numbers(void)
{
    uint32_t prime_cnt = 0;
    uint32_t total_sum = 0;
    uint32_t count     = 0;
    uint32_t x, y;

    for (x = 2; x <= 5; x++) {
        for (y = 2; y <= x; y++) {
            uint32_t ley = pow_u32(x, y) + pow_u32(y, x);
            total_sum += ley;
            if (leyland_is_prime(ley))
                prime_cnt++;
            count++;
        }
    }
    /* count=10, prime_cnt=1, total_sum=9092, total_sum%251=56 */
    (void)count;
    g_result = (10u << 16)
             | ((prime_cnt    & 0xFFu) << 8)
             | (total_sum % 251u);
}

__attribute__((noreturn)) void _start(void)
{
    test_leyland_numbers();
    for (;;);
}
