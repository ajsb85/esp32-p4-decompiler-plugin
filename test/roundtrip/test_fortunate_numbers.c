/* test_fortunate_numbers.c — Fortunate-number fixture
 * The n-th fortunate number F(n) is the smallest integer m > 1 such that
 * p_n# + m is prime, where p_n# is the primorial of the n-th prime.
 * Known values: F(1)=3 (2+3=5), F(2)=5 (6+5=11), F(3)=7 (30+7=37),
 *               F(4)=13 (210+13=223), F(5)=23 (2310+23=2333).
 * Strategy: compute each primorial, then find the smallest m >= 2 such
 * that primorial+m is prime (trial division).
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_fortunate_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FN_COUNT  5u   /* compute first 5 fortunate numbers */

static const uint32_t fn_primes[FN_COUNT] = { 2u, 3u, 5u, 7u, 11u };

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

static uint32_t fortunate_find(uint32_t primorial)
{
    /* smallest m >= 2 with primorial + m prime */
    for (uint32_t m = 2u; ; m++) {
        if (is_prime_fn(primorial + m)) return m;
    }
}

static void run_fortunate_numbers(void)
{
    uint32_t primorial    = 1u;
    uint32_t fn_sum       = 0u;   /* sum of all fortunate numbers found */
    uint32_t last_fn      = 0u;   /* last fortunate number (F(5)=23) */

    for (uint32_t i = 0u; i < FN_COUNT; i++) {
        primorial *= fn_primes[i];          /* p_n# */
        uint32_t fn = fortunate_find(primorial);
        fn_sum  += fn;
        last_fn  = fn;
    }

    /* F for primes 2,3,5,7,11: 3,5,7,13,23  →  sum=51=0x33, last=23=0x17
     * (2+3=5✓, 6+5=11✓, 30+7=37✓, 210+13=223✓, 2310+23=2333✓)
     * n_tests=5, metric_a=51&0xFF=0x33, metric_b=23=0x17
     * Bytes: 0x05, 0x33, 0x17 — all non-zero and distinct.          */
    uint32_t n_tests  = 5u;
    uint32_t metric_a = fn_sum  & 0xFFu;   /* 51 = 0x33 */
    uint32_t metric_b = last_fn & 0xFFu;   /* 23 = 0x17 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_fortunate_numbers();
    for (;;);
}
