/* test_pronic_numbers.c
 * Pronic (oblong) numbers: integers of the form n*(n+1) for n=0,1,2,...
 * These are products of two consecutive integers: 0, 2, 6, 12, 20, 30, ...
 *
 * In [1..199]: n*(n+1) <= 199 for n in [1..13] (14*15=210 > 199).
 * Values: 2, 6, 12, 20, 30, 42, 56, 72, 90, 110, 132, 156, 182
 *   count = 13, sum = 910
 *   metric_a = 13 & 0xFF = 0x0D
 *   metric_b = 910 % 251 = 157 = 0x9D
 *   n_tests  = 199 = 0xC7
 *   g_result = (199<<16)|(13<<8)|157 = 0x00C70D9D
 *   Bytes: 0xC7=199, 0x0D=13, 0x9D=157 — non-zero and distinct.
 *
 * Detection idiom: is_pronic checks floor(sqrt(n)) * (floor(sqrt(n))+1) == n
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_pronic_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Integer square root via Newton's method (32-bit safe) */
static uint32_t isqrt32(uint32_t n)
{
    if (n == 0u) return 0u;
    uint32_t x = n;
    uint32_t y = (x + 1u) >> 1u;
    while (y < x) {
        x = y;
        y = (x + n / x) >> 1u;
    }
    return x;
}

/* n is pronic iff there exists k such that k*(k+1) == n */
static uint32_t is_pronic(uint32_t n)
{
    if (n == 0u) return 1u;  /* 0 = 0*1 is pronic but we skip it (range starts at 1) */
    uint32_t k = isqrt32(n);
    /* Check k*(k+1) == n or (k-1)*k == n */
    if (k * (k + 1u) == n) return 1u;
    if (k > 0u && (k - 1u) * k == n) return 1u;
    return 0u;
}

void _start(void)
{
    uint32_t n_tests = 199u;
    uint32_t count   = 0u;
    uint32_t psum    = 0u;

    for (uint32_t n = 1u; n <= n_tests; n++) {
        if (is_pronic(n)) {
            count++;
            psum += n;
        }
    }

    /* In [1..199]: count=13, sum=910
     * metric_a = 13 & 0xFF  = 0x0D
     * metric_b = 910 % 251  = 157 = 0x9D
     * g_result = (199<<16)|(13<<8)|157 = 0x00C70D9D */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = psum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
