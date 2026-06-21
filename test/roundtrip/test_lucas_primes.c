/* test_lucas_primes.c — Lucas primes fixture
 * Lucas sequence: L(0)=2, L(1)=1, L(n)=L(n-1)+L(n-2).
 * Sequence: 2,1,3,4,7,11,18,29,47,76,123,199,322,521,843,1364,2207,3571,5778,9349.
 * Lucas primes (L(i) prime) in L(0)..L(19):
 *   L(0)=2, L(2)=3, L(4)=7, L(5)=11, L(7)=29, L(8)=47,
 *   L(11)=199, L(13)=521, L(16)=2207, L(17)=3571, L(19)=9349 → 11 primes.
 * Sum of Lucas primes mod 251: (2+3+7+11+29+47+199+521+2207+3571+9349)%251
 *   = 15946 % 251 = 15946 - 63*251 = 15946 - 15813 = 133 (0x85).
 * n_tests=20(0x14), metric_a=count_lp=11(0x0B), metric_b=133(0x85).
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_lucas_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LUC_N 20u

static uint32_t is_prime_lp(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_lucas_primes(void)
{
    uint32_t luc[LUC_N];
    luc[0] = 2u;
    luc[1] = 1u;
    for (uint32_t i = 2u; i < LUC_N; i++) {
        luc[i] = luc[i-1u] + luc[i-2u];
    }

    uint32_t count_lp  = 0u;
    uint32_t prime_sum = 0u;
    for (uint32_t i = 0u; i < LUC_N; i++) {
        if (is_prime_lp(luc[i])) {
            count_lp++;
            prime_sum += luc[i];
        }
    }
    /* prime_sum % 251: 15946 % 251 = 133 (0x85) */
    uint32_t checksum = prime_sum % 251u;

    uint32_t n_tests  = LUC_N & 0xFFu;     /* 0x14 */
    uint32_t metric_a = count_lp & 0xFFu;  /* 0x0B */
    uint32_t metric_b = checksum  & 0xFFu; /* 0x85 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_lucas_primes();
    for (;;);
}
