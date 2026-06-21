/* test_super_primes.c — Super-prime fixture
 * A super-prime (or prime-indexed prime) is a prime that occupies a prime
 * position in the sequence of all primes: p_2=3, p_3=5, p_5=11, p_7=17, ...
 * Strategy: build a small prime list up to SUPER_LIMIT, then for each prime
 * whose 1-based index is also prime, record it as a super-prime.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_super_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SP_LIMIT   200u
#define SP_MAX     64u   /* max primes we store */

static uint32_t primes[SP_MAX];
static uint32_t prime_cnt;

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

static void build_primes(void)
{
    prime_cnt = 0u;
    for (uint32_t n = 2u; n <= SP_LIMIT && prime_cnt < SP_MAX; n++) {
        if (is_prime_sp(n)) {
            primes[prime_cnt++] = n;
        }
    }
}

static void run_super_primes(void)
{
    build_primes();

    uint32_t sp_count = 0u;
    uint32_t last_sp  = 0u;

    /* 1-based index: primes[0] is p_1=2, primes[1] is p_2=3, etc.
     * super-prime if index (1-based) is itself prime.                */
    for (uint32_t i = 0u; i < prime_cnt; i++) {
        uint32_t idx = i + 1u;   /* 1-based index */
        if (is_prime_sp(idx)) {
            sp_count++;
            last_sp = primes[i];
        }
    }
    /* Primes <= 200: 2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,
     *   61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,
     *   151,157,163,167,173,179,181,191,193,197,199 → 46 primes.
     * Super-primes (prime-indexed): p_2=3, p_3=5, p_5=11, p_7=17, p_11=31,
     *   p_13=41, p_17=59, p_19=67, p_23=83, p_29=109, p_31=127, p_37=157,
     *   p_41=179, p_43=191 → 14 super-primes, last=191=0xBF
     * n_tests=3, metric_a=14=0x0E, metric_b=191&0xFF=0xBF
     * Bytes: 0x03, 0x0E, 0xBF — all non-zero and distinct.           */
    uint32_t n_tests  = 3u;
    uint32_t metric_a = sp_count & 0xFFu;   /* 14 = 0x0E */
    uint32_t metric_b = last_sp  & 0xFFu;   /* 191 = 0xBF */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_super_primes();
    for (;;);
}
