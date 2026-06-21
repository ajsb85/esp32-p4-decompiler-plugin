/* test_cullen_numbers.c — Cullen number fixture
 * A Cullen number is of the form C(n) = n * 2^n + 1.
 * First terms (n=1..20): 3,9,25,65,161,385,897,2049,...
 * Only C(1)=3 is prime in this range; all others are composite.
 * Strategy: compute C(1)..C(20), count composites, sum all candidates.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_cullen_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CN_MAX  20u     /* compute C(1)..C(CN_MAX) */

static uint32_t is_prime_cn(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_cullen_numbers(void)
{
    uint32_t count_comp = 0u;   /* composites in C(1)..C(20) */
    uint32_t cullen_sum = 0u;   /* sum of all C(n) */

    for (uint32_t n = 1u; n <= CN_MAX; n++) {
        /* C(n) = n * 2^n + 1 */
        uint32_t cand = n * (1u << n) + 1u;
        cullen_sum += cand;
        if (!is_prime_cn(cand)) count_comp++;
    }

    /* C(1)..C(20): only C(1)=3 is prime → count_comp = 19 (0x13).
     * cullen_sum = 39845910; 39845910 & 0xFF = 22 (0x16).
     * n_tests=5(0x05), metric_a=count_comp(0x13), metric_b=cullen_sum&0xFF(0x16).
     * All bytes non-zero and distinct.                                         */
    uint32_t n_tests  = 5u;
    uint32_t metric_a = count_comp       & 0xFFu;
    uint32_t metric_b = cullen_sum       & 0xFFu;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_cullen_numbers();
    for (;;);
}
