/* test_wagstaff_primes.c — Wagstaff-prime fixture
 * A Wagstaff prime is a prime of the form (2^p + 1) / 3 where p is an odd prime.
 * Known (p <= 31): p=3→3, p=5→11, p=7→43, p=11→683, p=13→2731,
 *   p=17→43691, p=19→174763, p=23→2796203, p=31→715827883.
 * Strategy: iterate odd primes p up to 31, compute (2^p+1)/3, verify primality.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_wagstaff_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define WP_PMAX  31u    /* largest odd prime exponent within uint32_t range */
#define WP_SLOTS 16u    /* max candidates to store                          */

static uint32_t is_prime_wp(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_wagstaff_primes(void)
{
    uint32_t wp_count = 0u;
    uint32_t last_wp  = 0u;

    /* Iterate odd primes p in [3, WP_PMAX].
     * (2^p + 1) is always divisible by 3 when p is odd:
     * 2 ≡ -1 (mod 3) ⟹ 2^p ≡ -1 (mod 3) ⟹ 2^p + 1 ≡ 0 (mod 3). */
    for (uint32_t p = 3u; p <= WP_PMAX; p += 2u) {
        if (!is_prime_wp(p)) continue;
        uint32_t pow2 = 1u << p;          /* p <= 31 ⟹ fits in uint32_t */
        uint32_t num  = pow2 + 1u;
        uint32_t cand = num / 3u;
        if (is_prime_wp(cand)) {
            wp_count++;
            last_wp = cand;
            if (wp_count >= WP_SLOTS) break;
        }
    }

    /* p=3..31 yields 9 Wagstaff primes; last is 715827883.
     * 715827883 & 0xFF = 0xAB = 171.
     * n_tests=5, metric_a=9 (0x09), metric_b=171 (0xAB).
     * Bytes: 0x05, 0x09, 0xAB — all non-zero and distinct.          */
    uint32_t n_tests  = 5u;
    uint32_t metric_a = wp_count & 0xFFu;
    uint32_t metric_b = last_wp  & 0xFFu;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_wagstaff_primes();
    for (;;);
}
