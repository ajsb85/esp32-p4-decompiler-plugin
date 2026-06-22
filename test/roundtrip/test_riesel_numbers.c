/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Riesel Numbers fixture.
 *
 * Riesel numbers: k values (odd) such that k*2^n - 1 is composite for
 * all n >= 1.  The first 10 proven Riesel numbers are stored as a
 * constant table; the fixture counts how many have (k>>8) > 100 (metric_a)
 * and computes the digit-sum of all 10 values mod 251 (metric_b).
 *
 * Distinctive decompiler idioms:
 *   1. Table of 10 known Riesel k values (small proven set)
 *   2. `(k >> 8) > 100` — high-byte threshold test
 *   3. Digit-sum loop: `while (v) { s += v%10; v /= 10; }`
 *
 * First 10 proven Riesel numbers:
 *   2293, 9221, 23669, 31859, 38473, 46663, 67117, 74699, 81041, 93839
 *
 * n_tests   = 10   = 0x0A
 * metric_a  =  7   = 0x07  (count where k>>8 > 100)
 * metric_b  = 235  = 0xEB  (digit_sum % 251)
 *
 * g_result = (10<<16)|(7<<8)|235 = 0x000A07EB
 */
#include <stdint.h>

volatile uint32_t g_result;

#define RIESEL_N 10

static const uint32_t riesel_k[RIESEL_N] = {
    2293, 9221, 23669, 31859, 38473,
    46663, 67117, 74699, 81041, 93839
};

static uint32_t riesel_digit_sum(uint32_t v)
{
    uint32_t s = 0;
    while (v > 0) {
        s += v % 10;
        v /= 10;
    }
    return s;
}

void test_riesel_numbers(void)
{
    uint32_t cnt_large = 0;
    uint32_t dig_sum   = 0;
    uint32_t i;

    for (i = 0; i < RIESEL_N; i++) {
        if ((riesel_k[i] >> 8) > 100u)
            cnt_large++;
        dig_sum += riesel_digit_sum(riesel_k[i]);
    }

    /* n_tests=10=0x0A, metric_a=7=0x07, metric_b=235=0xEB */
    g_result = ((uint32_t)RIESEL_N << 16)
             | ((cnt_large & 0xFFu) << 8)
             | (dig_sum % 251u);
}

__attribute__((noreturn)) void _start(void)
{
    test_riesel_numbers();
    for (;;);
}
