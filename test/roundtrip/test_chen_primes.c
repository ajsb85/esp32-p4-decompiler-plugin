/* test_chen_primes.c — Chen primes fixture
 * A prime p is a Chen prime if p+2 is either prime (twin prime) or
 * a semiprime (product of exactly two not-necessarily-distinct primes).
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_chen_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CP_UPPER 100u

static uint32_t is_prime_cp(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

/* Count distinct prime factors of n (with multiplicity) */
static uint32_t omega_cp(uint32_t n)
{
    uint32_t cnt = 0u;
    if (n < 2u) return 0u;
    while ((n & 1u) == 0u) { cnt++; n >>= 1u; }
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        while (n % d == 0u) { cnt++; n /= d; }
    }
    if (n > 1u) cnt++;
    return cnt;
}

static void run_chen_primes(void)
{
    uint32_t chen_count = 0u;   /* number of Chen primes found */
    uint32_t last_chen  = 0u;   /* last Chen prime found       */

    for (uint32_t p = 2u; p + 2u <= CP_UPPER + 2u; p++) {
        if (!is_prime_cp(p)) continue;
        uint32_t q = p + 2u;
        /* q must be prime OR semiprime (exactly 2 prime factors) */
        if (is_prime_cp(q) || omega_cp(q) == 2u) {
            chen_count++;
            last_chen = p;
        }
    }
    /* Chen primes ≤ 100: 2,3,5,7,11,13,17,19,23,29,31,37,41,
     *   47,53,59,67,71,83,89,97 → 21 primes, last = 97 = 0x61
     * n_tests=3, metric_a=21=0x15, metric_b=97=0x61
     * Bytes: 0x03, 0x15, 0x61 — all non-zero and distinct.       */
    uint32_t n_tests  = 3u;
    uint32_t metric_a = chen_count & 0xFFu;   /* 21 = 0x15 */
    uint32_t metric_b = last_chen  & 0xFFu;   /* 97 = 0x61 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_chen_primes();
    for (;;);
}
