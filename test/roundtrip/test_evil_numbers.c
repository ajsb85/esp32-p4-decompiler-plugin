/* test_evil_numbers.c
 * Evil numbers: non-negative integers with an even number of 1-bits in their
 * binary representation (even Hamming weight / even popcount).
 * The complement of odious numbers (among positive integers).
 *
 * In [1..99]:
 *   count  = 49  (integers 1..99 with even popcount)
 *   sum    = 2475
 *   metric_a = 49  & 0xFF = 0x31
 *   metric_b = 2475 % 251  = 216 = 0xD8
 *   n_tests  = 99           = 0x63
 *   g_result = (99<<16)|(49<<8)|216 = 0x006331D8
 *   Bytes: 0x63=99, 0x31=49, 0xD8=216 — non-zero and distinct.
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_evil_numbers.c
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

/* Return 1 if n is evil (even popcount), 0 otherwise.
 * Note: 0 has popcount 0 (even) but we exclude it per convention. */
static uint32_t is_evil(uint32_t n)
{
    return (popcount32(n) & 1u) == 0u;
}

void _start(void)
{
    uint32_t n_tests = 99u;
    uint32_t count   = 0u;
    uint32_t esum    = 0u;

    for (uint32_t n = 1u; n <= n_tests; n++) {
        if (is_evil(n)) {
            count++;
            esum += n;
        }
    }

    /* In [1..99]: count=49, sum=2475
     * metric_a = 49  & 0xFF   = 0x31
     * metric_b = 2475 % 251   = 216 = 0xD8
     * g_result = (99<<16)|(49<<8)|216 = 0x006331D8 */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = esum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
