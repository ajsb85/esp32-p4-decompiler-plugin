/* test_fibonacci_primes.c — Fibonacci primes fixture
 * A Fibonacci prime is a Fibonacci number that is also prime.
 * Sequence F(0)=0,F(1)=1,F(n)=F(n-1)+F(n-2).
 * Among F(0)..F(19): primes are F(3)=2,F(4)=3,F(5)=5,F(7)=13,
 *   F(11)=89,F(13)=233,F(17)=1597 → 7 Fibonacci primes.
 * Sum of those primes = 2+3+5+13+89+233+1597 = 1942.
 * 1942 % 251 = 1942 - 7*251 = 1942 - 1757 = 185 (0xB9).
 * n_tests=20(0x14), metric_a=count_fp=7(0x07), metric_b=185(0xB9).
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_fibonacci_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FIB_N 20u

static uint32_t is_prime_fp(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_fibonacci_primes(void)
{
    uint32_t fib[FIB_N];
    fib[0] = 0u;
    fib[1] = 1u;
    for (uint32_t i = 2u; i < FIB_N; i++) {
        fib[i] = fib[i-1u] + fib[i-2u];
    }

    uint32_t count_fp = 0u;
    uint32_t prime_sum = 0u;
    for (uint32_t i = 0u; i < FIB_N; i++) {
        if (is_prime_fp(fib[i])) {
            count_fp++;
            prime_sum += fib[i];
        }
    }
    /* prime_sum % 251: 1942 % 251 = 185 (0xB9) */
    uint32_t checksum = prime_sum % 251u;

    uint32_t n_tests  = FIB_N & 0xFFu;      /* 0x14 */
    uint32_t metric_a = count_fp & 0xFFu;   /* 0x07 */
    uint32_t metric_b = checksum  & 0xFFu;  /* 0xB9 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_fibonacci_primes();
    for (;;);
}
