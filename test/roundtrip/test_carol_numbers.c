/* test_carol_numbers.c — Carol-number prime fixture
 * A Carol number is of the form (2^n - 1)^2 - 2.
 * Carol primes (n up to 15, values fit in uint32_t):
 *   n=2→7, n=3→47, n=4→223, n=6→3967, n=7→16127,
 *   n=10→1046527, n=12→16769023, n=15→1073676287.
 * Strategy: compute (2^n-1)^2-2 for n in [2,15], test primality, count results.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_carol_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CN_NMAX  15u    /* max exponent n (values fit in uint32_t up to n=15) */
#define CN_SLOTS 16u    /* max primes to store                                 */

static uint32_t is_prime_cn(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_carol_numbers(void)
{
    uint32_t cn_count = 0u;
    uint32_t last_cn  = 0u;

    for (uint32_t n = 2u; n <= CN_NMAX; n++) {
        uint32_t m    = (1u << n) - 1u;   /* 2^n - 1 */
        uint32_t cand = m * m - 2u;       /* (2^n - 1)^2 - 2 */
        /* (2^15-1)^2 = 32767^2 = 1073676289; -2 = 1073676287 < 2^30, fits u32 */
        if (is_prime_cn(cand)) {
            cn_count++;
            last_cn = cand;
            if (cn_count >= CN_SLOTS) break;
        }
    }

    /* n in [2,15] yields 8 Carol primes; last is 1073676287.
     * 1073676287 & 0xFF = 0xFF = 255.
     * n_tests=4, metric_a=8 (0x08), metric_b=255 (0xFF).
     * Bytes: 0x04, 0x08, 0xFF — all non-zero and distinct.          */
    uint32_t n_tests  = 4u;
    uint32_t metric_a = cn_count & 0xFFu;
    uint32_t metric_b = last_cn  & 0xFFu;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_carol_numbers();
    for (;;);
}
