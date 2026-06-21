/* test_sexy_primes.c — Sexy primes (prime pairs differing by 6) fixture
 * A pair (p, p+6) is sexy if both p and p+6 are prime.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_sexy_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SP_UPPER 200u

static uint32_t is_prime_sp(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_sexy_primes(void)
{
    uint32_t sp_count = 0u;   /* number of sexy prime pairs found */
    uint32_t last_p   = 0u;   /* smaller prime of last sexy pair  */

    for (uint32_t p = 2u; p + 6u <= SP_UPPER; p++) {
        if (is_prime_sp(p) && is_prime_sp(p + 6u)) {
            sp_count++;
            last_p = p;
        }
    }
    /* Pairs up to 200: (5,11),(7,13),(11,17),(13,19),(17,23),(23,29),(31,37),
     * (37,43),(41,47),(47,53),(53,59),(61,67),(67,73),(73,79),(83,89),(97,103),
     * (101,107),(103,109),(107,113),(131,137),(151,157),(157,163),(167,173),
     * (173,179),(191,197),(193,199) → 26 pairs, last_p=193
     * n_tests=3, metric_a=sp_count&0xFF=0x1A(26), metric_b=last_p&0xFF=0xC1(193)
     * Bytes: 0x03, 0x1A, 0xC1 — all non-zero and distinct.               */
    uint32_t n_tests  = 3u;
    uint32_t metric_a = sp_count & 0xFFu;   /* 26 = 0x1A */
    uint32_t metric_b = last_p   & 0xFFu;   /* 193 = 0xC1 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_sexy_primes();
    for (;;);
}
