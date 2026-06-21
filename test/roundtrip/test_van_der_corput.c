/* test_van_der_corput.c
 * Van der Corput sequence in base b: reflect the base-b digits of n around
 * the decimal point.  For base 2: reverse the bits of n and divide by 2^bits.
 * We work in fixed-point integer arithmetic (multiply by 2^16 to avoid floats).
 * vdc_fixed(n, base) returns floor(vdc(n,base) * 65536) as uint32_t.
 * The sequence in base 2: 0, 1/2, 1/4, 3/4, 1/8, 5/8, 3/8, 7/8, ...
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_van_der_corput.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SCALE 65536U  /* fixed-point scale = 2^16 */

/* Compute Van der Corput value for index n in given base,
 * returned as fixed-point integer (multiply by SCALE).
 * n=0 maps to 0, n=1 maps to 1/base, etc.
 */
static uint32_t vdc_fixed(uint32_t n, uint32_t base) {
    uint32_t num = 0;
    uint32_t denom = 1;  /* tracks base^k */
    while (n > 0) {
        uint32_t digit = n % base;
        n /= base;
        denom *= base;
        num = num * base + digit;
    }
    /* value = num / denom; fixed-point = num * SCALE / denom */
    /* Use 32-bit: num < denom <= base^10, SCALE=65536 */
    /* For base 2, max denom = 2^16 for n<65536, but we only go to n=16 */
    if (denom == 0) return 0;
    return (num * SCALE) / denom;
}

void _start(void) {
    /* Compute VDC sequence in base 2 for n=1..16 */
    uint32_t vdc2[16];
    uint32_t i;
    for (i = 0; i < 16; i++) {
        vdc2[i] = vdc_fixed(i + 1, 2);
    }

    /* Compute VDC sequence in base 3 for n=1..16 */
    uint32_t vdc3[16];
    for (i = 0; i < 16; i++) {
        vdc3[i] = vdc_fixed(i + 1, 3);
    }

    /* Accumulate metrics */
    uint32_t sum2 = 0, sum3 = 0;
    uint32_t xor_acc = 0;
    for (i = 0; i < 16; i++) {
        sum2 = (sum2 + vdc2[i]) % 256U;
        sum3 = (sum3 + vdc3[i]) % 256U;
        xor_acc ^= (vdc2[i] ^ vdc3[i]);
    }

    /* Count pairs where vdc2[i] + vdc3[i] < SCALE (both < 1.0) -- always true */
    uint32_t below_one = 0;
    for (i = 0; i < 16; i++) {
        if (vdc2[i] < SCALE && vdc3[i] < SCALE) below_one++;
    }

    uint32_t n_tests  = 16;
    uint32_t metric_a = ((sum2 + sum3 + below_one) & 0xFF);
    uint32_t metric_b = (xor_acc & 0xFF);

    if (metric_a == 0) metric_a = 1;
    if (metric_b == 0) metric_b = 2;
    if (metric_a == n_tests) metric_a = (metric_a + 1) & 0xFF;
    if (metric_b == n_tests || metric_b == metric_a) metric_b = (metric_b + 5) & 0xFF;
    if (metric_b == 0) metric_b = 9;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;

    while (1) {}
}
