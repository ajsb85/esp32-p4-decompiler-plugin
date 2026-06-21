/* test_sophie_germain_primes.c — Sophie Germain primes fixture
 * A prime p is a Sophie Germain prime if 2*p+1 is also prime (a safe prime).
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_sophie_germain_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SGP_UPPER 250u

static uint32_t is_prime_sgp(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_sophie_germain(void)
{
    uint32_t sg_count = 0u;   /* count of Sophie Germain primes */
    uint32_t last_sg  = 0u;   /* last Sophie Germain prime found */

    for (uint32_t p = 2u; p <= SGP_UPPER; p++) {
        if (is_prime_sgp(p) && is_prime_sgp(2u * p + 1u)) {
            sg_count++;
            last_sg = p;
        }
    }
    /* Sophie Germain primes <= 250: 2,3,5,11,23,29,41,53,83,89,113,131,173,
     *   179,191,233 — count=16=0x10, last=233=0xE9
     * n_tests=3, metric_a=sg_count&0xFF=0x10, metric_b=last_sg&0xFF=0xE9
     * Bytes: 0x03, 0x10, 0xE9 — all non-zero and distinct.               */
    uint32_t n_tests  = 3u;
    uint32_t metric_a = sg_count & 0xFFu;   /* 16 = 0x10 */
    uint32_t metric_b = last_sg  & 0xFFu;   /* 233 & 0xFF = 0xE9 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_sophie_germain();
    for (;;);
}
