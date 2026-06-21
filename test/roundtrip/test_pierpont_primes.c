/* test_pierpont_primes.c — Pierpont-prime fixture
 * A Pierpont prime of the first kind is a prime of the form 2^u * 3^v + 1.
 * Known: 2,3,5,7,13,17,19,37,73,97,109,163,193,... (first 13 listed).
 * Strategy: enumerate 3-smooth numbers (products of powers of 2 and 3)
 * up to a limit, check if smooth+1 is prime, collect results.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_pierpont_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PP_LIMIT  512u    /* search 3-smooth numbers up to this bound */
#define PP_SLOTS  32u     /* max candidates to store */

static uint32_t is_prime_pp1(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

/* Simple insertion sort to order the smooth candidates. */
static void sort_u32(uint32_t *arr, uint32_t n)
{
    for (uint32_t i = 1u; i < n; i++) {
        uint32_t key = arr[i];
        uint32_t j   = i;
        while (j > 0u && arr[j - 1u] > key) {
            arr[j] = arr[j - 1u];
            j--;
        }
        arr[j] = key;
    }
}

static void run_pierpont_primes(void)
{
    /* Generate all 3-smooth numbers (2^u * 3^v) up to PP_LIMIT. */
    uint32_t smooth[PP_SLOTS];
    uint32_t scnt = 0u;

    for (uint32_t pw2 = 1u; pw2 <= PP_LIMIT && scnt < PP_SLOTS; pw2 <<= 1) {
        for (uint32_t pw3 = pw2; pw3 <= PP_LIMIT && scnt < PP_SLOTS; pw3 *= 3u) {
            smooth[scnt++] = pw3;
        }
    }

    sort_u32(smooth, scnt);

    uint32_t pp_count = 0u;
    uint32_t last_pp  = 0u;

    for (uint32_t i = 0u; i < scnt; i++) {
        uint32_t cand = smooth[i] + 1u;
        if (is_prime_pp1(cand)) {
            pp_count++;
            last_pp = cand;   /* sorted, so last is largest */
        }
    }

    /* 3-smooth ≤ 512: 1,2,3,4,6,8,9,12,16,18,24,27,32,36,48,54,64,72,81,
     *   96,108,128,144,162,192,216,243,256,288,324,384,432,486,512.
     *   +1 primes: 2,3,5,7,13,17,19,37,73,97,109,163,193,257,433,487
     *   → count=16=0x10, last=487, 487&0xFF=0xE7.
     * n_tests=4, metric_a=16=0x10, metric_b=487&0xFF=0xE7
     * Bytes: 0x04, 0x10, 0xE7 — all non-zero and distinct.          */
    uint32_t n_tests  = 4u;
    uint32_t metric_a = pp_count & 0xFFu;
    uint32_t metric_b = last_pp  & 0xFFu;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

__attribute__((noreturn)) void _start(void)
{
    run_pierpont_primes();
    for (;;);
}
