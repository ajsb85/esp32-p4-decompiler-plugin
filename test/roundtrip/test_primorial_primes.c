/* test_primorial_primes.c — Primorial-prime fixture
 * A primorial prime is a prime of the form p# + 1 or p# - 1, where p# is
 * the product of all primes up to p.  Known primorial primes: 2#+1=3,
 * 3#+1=7, 5#+1=31, 2#-1=1(no), 3#-1=5, 5#-1=29, 7#-1=209(no), ...
 * Strategy: iterate over small primes, compute running primorial (mod stays
 * in 32 bits up to 7# = 210), test ±1 for primality, count and record.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_primorial_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Primes to iterate: 2,3,5,7 — 7#=210, 11# overflows comfortable 32-bit. */
#define PRIM_BASE_COUNT 4u

static const uint32_t prim_bases[PRIM_BASE_COUNT] = { 2u, 3u, 5u, 7u };

static uint32_t is_prime_pp(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_primorial_primes(void)
{
    uint32_t primorial = 1u;
    uint32_t count     = 0u;   /* total primorial primes found (+1 and -1) */
    uint32_t last_pp   = 0u;   /* largest primorial prime found */

    for (uint32_t i = 0u; i < PRIM_BASE_COUNT; i++) {
        primorial *= prim_bases[i];   /* running product */

        /* Check p# + 1 */
        uint32_t cand_plus = primorial + 1u;
        if (is_prime_pp(cand_plus)) {
            count++;
            if (cand_plus > last_pp) last_pp = cand_plus;
        }

        /* Check p# - 1 (guard against underflow on 2#-1=1) */
        if (primorial > 1u) {
            uint32_t cand_minus = primorial - 1u;
            if (is_prime_pp(cand_minus)) {
                count++;
                if (cand_minus > last_pp) last_pp = cand_minus;
            }
        }
    }

    /* Results:
     *   2#=2: 3(prime ✓), 1(no)         → +1 hit: 3
     *   3#=6: 7(prime ✓), 5(prime ✓)    → +2 hits: 7,5
     *   5#=30: 31(prime ✓), 29(prime ✓) → +2 hits: 31,29
     *   7#=210: 211(prime ✓), 209=11×19(no) → +1 hit: 211
     *   Total count = 6, last_pp = 211 = 0xD3
     * n_tests=3, metric_a=6=0x06, metric_b=211&0xFF=0xD3
     * Bytes: 0x03, 0x06, 0xD3 — all non-zero and distinct.          */
    uint32_t n_tests  = 3u;
    uint32_t metric_a = count    & 0xFFu;   /* 6 = 0x06 */
    uint32_t metric_b = last_pp  & 0xFFu;   /* 211 = 0xD3 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_primorial_primes();
    for (;;);
}
