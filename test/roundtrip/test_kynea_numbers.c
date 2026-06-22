/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Kynea Numbers fixture.
 *
 * Kynea number for index n: (2^n + 1)^2 - 2
 * First six values: 7, 23, 79, 287, 1087, 4223
 *
 * Distinctive decompiler idioms:
 *   1. `pow2 <<= 1` — doubling loop to compute 2^n
 *   2. `(pow2 + 1) * (pow2 + 1) - 2` — Kynea formula
 *   3. Trial-division primality test on each Kynea value
 *
 * Results for n=1..6:
 *   7(prime), 23(prime), 79(prime), 287(composite), 1087(prime), 4223(composite)
 *
 * n_tests   = 6  = 0x06
 * metric_a  = 4  = 0x04  (prime count)
 * metric_b  = 2  = 0x02  (composite count)
 *
 * g_result = (6<<16)|(4<<8)|2 = 0x00060402
 */
#include <stdint.h>

volatile uint32_t g_result;

#define KYNEA_N 6

static uint32_t kynea_is_prime(uint32_t n)
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

void test_kynea_numbers(void)
{
    uint32_t prime_cnt     = 0;
    uint32_t composite_cnt = 0;
    uint32_t pow2 = 2u;
    uint32_t n;

    for (n = 1; n <= KYNEA_N; n++) {
        uint32_t kval = (pow2 + 1u) * (pow2 + 1u) - 2u;
        if (kynea_is_prime(kval))
            prime_cnt++;
        else
            composite_cnt++;
        pow2 <<= 1;
    }

    /* n_tests=6=0x06, metric_a=4=0x04, metric_b=2=0x02 */
    g_result = ((uint32_t)KYNEA_N << 16)
             | ((prime_cnt     & 0xFFu) << 8)
             | (composite_cnt  & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_kynea_numbers();
    for (;;);
}
