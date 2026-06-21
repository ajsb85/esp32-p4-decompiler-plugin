/* test_thabit_numbers.c — Thabit-number prime fixture
 * A Thabit number (of the first kind) is of the form 3 * 2^n - 1.
 * Thabit primes (n in [0,18], values fit in uint32_t):
 *   n=0→2, n=1→5, n=2→11, n=3→23, n=4→47,
 *   n=6→191, n=7→383, n=11→6143, n=18→786431.
 * Strategy: compute 3*2^n-1 for n in [0,28], test primality, count results.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_thabit_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TN_NMAX  28u    /* max exponent (3*2^28-1 = 805306367, fits uint32_t) */
#define TN_SLOTS 16u    /* max primes to store                                 */

static uint32_t is_prime_tn(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

static void run_thabit_numbers(void)
{
    uint32_t tn_count = 0u;
    uint32_t last_tn  = 0u;

    for (uint32_t n = 0u; n <= TN_NMAX; n++) {
        /* 3 * 2^n - 1 */
        uint32_t cand = 3u * (1u << n) - 1u;
        if (is_prime_tn(cand)) {
            tn_count++;
            last_tn = cand;
            if (tn_count >= TN_SLOTS) break;
        }
    }

    /* n in [0,28] yields 9 Thabit primes; last is 786431.
     * 786431 & 0xFF = 0xFF = 255.
     * n_tests=5, metric_a=9 (0x09), metric_b=255 (0xFF).
     * Bytes: 0x05, 0x09, 0xFF — all non-zero and distinct.          */
    uint32_t n_tests  = 5u;
    uint32_t metric_a = tn_count & 0xFFu;
    uint32_t metric_b = last_tn  & 0xFFu;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_thabit_numbers();
    for (;;);
}
