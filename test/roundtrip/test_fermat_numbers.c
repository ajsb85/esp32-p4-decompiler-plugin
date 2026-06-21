/* test_fermat_numbers.c — Fermat number fixture
 * A Fermat number is F(n) = 2^(2^n) + 1.
 * F(0)=3, F(1)=5, F(2)=17, F(3)=257, F(4)=65537 — all prime (uint32_t range).
 * F(5) = 2^32+1 overflows uint32_t; we stop at n=4.
 * Strategy: compute F(0)..F(4), verify all are prime, sum them.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_fermat_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FN_MAX  4u      /* compute F(0)..F(FN_MAX) */

static uint32_t is_prime_fn(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_fermat_numbers(void)
{
    uint32_t count_prime = 0u;
    uint32_t fermat_sum  = 0u;

    for (uint32_t n = 0u; n <= FN_MAX; n++) {
        /* F(n) = 2^(2^n) + 1; exponent 2^n fits in [1,16] for n in [0,4] */
        uint32_t exp  = 1u << n;          /* 2^n */
        uint32_t cand = (1u << exp) + 1u; /* 2^(2^n) + 1 */
        fermat_sum += cand;
        if (is_prime_fn(cand)) count_prime++;
    }

    /* F(0)..F(4) all prime → count_prime=5 (0x05).
     * fermat_sum = 3+5+17+257+65537 = 65819; 65819 & 0xFF = 27 (0x1B).
     * n_tests=4(0x04), metric_a=count_prime(0x05), metric_b=fermat_sum&0xFF(0x1B).
     * All bytes non-zero and distinct.                                         */
    uint32_t n_tests  = 4u;
    uint32_t metric_a = count_prime & 0xFFu;
    uint32_t metric_b = fermat_sum  & 0xFFu;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_fermat_numbers();
    for (;;);
}
