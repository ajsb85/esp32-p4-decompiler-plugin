/* test_safe_primes.c — Safe primes fixture
 * A safe prime p satisfies: p is prime AND (p-1)/2 is also prime.
 * The value (p-1)/2 is called a Sophie Germain prime.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_safe_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SAFE_UPPER 300u

static uint32_t is_prime_safe(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_safe_primes(void)
{
    uint32_t safe_count = 0u;   /* count of safe primes found */
    uint32_t last_safe  = 0u;   /* last safe prime found       */

    for (uint32_t p = 5u; p <= SAFE_UPPER; p += 2u) {
        if (is_prime_safe(p) && is_prime_safe((p - 1u) >> 1u)) {
            safe_count++;
            last_safe = p;
        }
    }
    /* Safe primes ≤ 300: 5,7,11,23,47,59,83,107,167,179,227,263,
     *   (p-1)/2 must also be prime: 2,3,5,11,23,29,41,53,83,89,113,131)
     * Count = 12 safe primes, last = 263 = 0x107 → &0xFF = 0x07
     * n_tests=3, metric_a=12=0x0C, metric_b=last_safe&0xFF=0x07
     * Bytes: 0x03, 0x0C, 0x07 — all non-zero and distinct.             */
    uint32_t n_tests  = 3u;
    uint32_t metric_a = safe_count & 0xFFu;   /* 12 = 0x0C */
    uint32_t metric_b = last_safe  & 0xFFu;   /* 263 & 0xFF = 0x07 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_safe_primes();
    for (;;);
}
