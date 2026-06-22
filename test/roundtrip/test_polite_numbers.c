/* test_polite_numbers.c
 * Polite numbers: positive integers that can be expressed as a sum of two or more
 * consecutive positive integers.  A positive integer is impolite iff it is a
 * power of two (including 2^0 = 1).  All other positive integers are polite.
 *
 * Powers of 2 in [1..199]: 1, 2, 4, 8, 16, 32, 64, 128  → 8 impolite values.
 * Polite numbers in [1..199]: 199 - 8 = 191 values.
 * Sum of polite numbers in [1..199]:
 *   sum([1..199]) - (1+2+4+8+16+32+64+128) = 19900 - 255 = 19645
 *   metric_a = 191 & 0xFF  = 0xBF
 *   metric_b = 19645 % 251 = 67  = 0x43
 *   n_tests  = 199          = 0xC7
 *   g_result = (199<<16)|(191<<8)|67 = 0x00C7BF43
 *   Bytes: 0xC7=199, 0xBF=191, 0x43=67 — non-zero and distinct.
 *
 * Detection idiom: n is impolite iff (n & (n-1)) == 0  (power-of-two test).
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_polite_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Returns 1 if n is a power of two (impolite), 0 otherwise */
static uint32_t is_power_of_two(uint32_t n)
{
    return (n > 0u) && ((n & (n - 1u)) == 0u);
}

/* Returns 1 if n is polite (not a power of two, and n > 0) */
static uint32_t is_polite(uint32_t n)
{
    if (n == 0u) return 0u;
    return !is_power_of_two(n);
}

void _start(void)
{
    uint32_t n_tests = 199u;
    uint32_t count   = 0u;
    uint32_t psum    = 0u;

    for (uint32_t n = 1u; n <= n_tests; n++) {
        if (is_polite(n)) {
            count++;
            psum += n;
        }
    }

    /* In [1..199]: count=191, sum=19645
     * metric_a = 191 & 0xFF = 0xBF
     * metric_b = 19645 % 251 = 67 = 0x43
     * g_result = (199<<16)|(191<<8)|67 = 0x00C7BF43 */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = psum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
