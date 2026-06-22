/* test_odious_numbers.c
 * Odious numbers: positive integers with an odd number of 1-bits in their
 * binary representation (odd Hamming weight / odd popcount).
 *
 * In [1..99]:
 *   count  = 50  (exactly half the integers 1..99 have odd popcount)
 *   sum    = 2475
 *   metric_a = 50  & 0xFF = 0x32
 *   metric_b = 2475 % 251  = 216 = 0xD8
 *   n_tests  = 99           = 0x63
 *   g_result = (99<<16)|(50<<8)|216 = 0x006332D8
 *   Bytes: 0x63=99, 0x32=50, 0xD8=216 — non-zero and distinct.
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_odious_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Count the number of 1-bits in n (32-bit popcount). */
static uint32_t popcount32(uint32_t n)
{
    n = n - ((n >> 1u) & 0x55555555u);
    n = (n & 0x33333333u) + ((n >> 2u) & 0x33333333u);
    n = (n + (n >> 4u)) & 0x0F0F0F0Fu;
    n = (n * 0x01010101u) >> 24u;
    return n;
}

/* Return 1 if n is odious (odd popcount), 0 otherwise. */
static uint32_t is_odious(uint32_t n)
{
    return popcount32(n) & 1u;
}

void _start(void)
{
    uint32_t n_tests = 99u;
    uint32_t count   = 0u;
    uint32_t osum    = 0u;

    for (uint32_t n = 1u; n <= n_tests; n++) {
        if (is_odious(n)) {
            count++;
            osum += n;
        }
    }

    /* In [1..99]: count=50, sum=2475
     * metric_a = 50  & 0xFF   = 0x32
     * metric_b = 2475 % 251   = 216 = 0xD8
     * g_result = (99<<16)|(50<<8)|216 = 0x006332D8 */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = osum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
