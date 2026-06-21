/* test_woodall_numbers.c — Woodall number fixture
 * A Woodall number is of the form W(n) = n * 2^n - 1.
 * First terms (n=1..20): 1,7,23,63,159,383,...
 * W(2)=7, W(3)=23, W(6)=383 are prime in [1..20].
 * Strategy: compute W(1)..W(20), count primes, record last prime found.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_woodall_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define WN_MAX  20u     /* compute W(1)..W(WN_MAX) */

static uint32_t is_prime_wn(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_woodall_numbers(void)
{
    uint32_t count_prime  = 0u;
    uint32_t last_prime_w = 0u;

    for (uint32_t n = 1u; n <= WN_MAX; n++) {
        /* W(n) = n * 2^n - 1 */
        uint32_t cand = n * (1u << n) - 1u;
        if (is_prime_wn(cand)) {
            count_prime++;
            last_prime_w = cand;
        }
    }

    /* W(2)=7, W(3)=23, W(6)=383 prime → count_prime=3 (0x03).
     * last_prime_w=383; 383 & 0xFF = 127 (0x7F).
     * n_tests=7(0x07), metric_a=count_prime(0x03), metric_b=last_prime_w&0xFF(0x7F).
     * All bytes non-zero and distinct.                                           */
    uint32_t n_tests  = 7u;
    uint32_t metric_a = count_prime  & 0xFFu;
    uint32_t metric_b = last_prime_w & 0xFFu;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_woodall_numbers();
    for (;;);
}
