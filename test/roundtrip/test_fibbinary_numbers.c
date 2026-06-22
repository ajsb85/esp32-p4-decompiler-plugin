/* test_fibbinary_numbers.c
 * Fibbinary numbers: non-negative integers whose binary representation
 * contains no two consecutive 1-bits.  Equivalently, n & (n >> 1) == 0.
 * These are the indices of 1s in the Fibonacci representation (Zeckendorf).
 * The count of fibbinary numbers in [0..F(k+2)-2] equals F(k).
 *
 * In [1..99]:
 *   count  = 33
 *   sum    = 1389
 *   metric_a = 33  & 0xFF = 0x21
 *   metric_b = 1389 % 251  = 134 = 0x86
 *   n_tests  = 99           = 0x63
 *   g_result = (99<<16)|(33<<8)|134 = 0x00632186
 *   Bytes: 0x63=99, 0x21=33, 0x86=134 — non-zero and distinct.
 *
 * Fibbinary numbers in [1..99]:
 *   1,2,4,5,8,9,10,16,17,18,20,21,32,33,34,36,37,40,41,42,
 *   64,65,66,68,69,72,73,74,80,81,82,84,85 = 33 values.
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_fibbinary_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Return 1 if n is a fibbinary number (no two consecutive 1-bits). */
static uint32_t is_fibbinary(uint32_t n)
{
    return (n & (n >> 1u)) == 0u;
}

void _start(void)
{
    uint32_t n_tests = 99u;
    uint32_t count   = 0u;
    uint32_t fsum    = 0u;

    for (uint32_t n = 1u; n <= n_tests; n++) {
        if (is_fibbinary(n)) {
            count++;
            fsum += n;
        }
    }

    /* In [1..99]: count=33, sum=1389
     * metric_a = 33  & 0xFF   = 0x21
     * metric_b = 1389 % 251   = 134 = 0x86
     * g_result = (99<<16)|(33<<8)|134 = 0x00632186 */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = fsum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
