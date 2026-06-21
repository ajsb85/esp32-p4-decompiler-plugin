/* test_sierpinski_numbers.c — Sierpinski numbers fixture
 * A Sierpinski candidate is an odd k such that k*2^n+1 is composite for
 * all tested n. We check odd k in [1,99] (50 candidates), testing n=1..6.
 * Candidates where ALL of k*2^1+1 .. k*2^6+1 are composite: k=31,47,91.
 * count_s = 3 (0x03). Sum of candidates = 31+47+91 = 169 (0xA9).
 * n_tests=50(0x32), metric_a=count_s=3(0x03), metric_b=169(0xA9).
 * All bytes non-zero and distinct.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_sierpinski_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define K_MAX   99u   /* check odd k from 1 to K_MAX */
#define N_EXP   6u    /* test n = 1 .. N_EXP */

static uint32_t is_prime_sn(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_sierpinski_numbers(void)
{
    uint32_t count_s  = 0u;
    uint32_t cand_sum = 0u;

    for (uint32_t k = 1u; k <= K_MAX; k += 2u) {   /* odd k only */
        uint32_t all_composite = 1u;
        for (uint32_t n = 1u; n <= N_EXP; n++) {
            uint32_t val = k * (1u << n) + 1u;
            if (is_prime_sn(val)) {
                all_composite = 0u;
                break;
            }
        }
        if (all_composite) {
            count_s++;
            cand_sum += k;
        }
    }

    /* count_s=3(0x03), cand_sum=169(0xA9). n_tests = (K_MAX+1)/2 = 50(0x32). */
    uint32_t n_tests  = ((K_MAX + 1u) / 2u) & 0xFFu; /* 0x32 */
    uint32_t metric_a = count_s  & 0xFFu;             /* 0x03 */
    uint32_t metric_b = cand_sum & 0xFFu;             /* 0xA9 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_sierpinski_numbers();
    for (;;);
}
