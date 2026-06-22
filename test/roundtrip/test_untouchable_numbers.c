/* test_untouchable_numbers.c
 * Untouchable numbers: positive integers that cannot be expressed as the
 * sum of proper divisors of any positive integer.
 * Equivalently, n is untouchable if there is no m with s(m) = n,
 * where s(m) = sigma(m) - m (sum of proper divisors of m).
 *
 * Untouchable numbers in [2..200]:
 *   2, 5, 52, 88, 96, 120, 124, 146, 162, 188
 *   count=10, sum=983; metric_a=10, metric_b=983%251=230
 *   g_result = (199<<16)|(10<<8)|230 = 0x00C70AE6
 *   Bytes: 0xC7=199, 0x0A=10, 0xE6=230 — non-zero and distinct.
 *
 * Algorithm: sieve s(m) for m in [2..SIEVE_LIMIT] and mark reachable values.
 * SIEVE_LIMIT=50000 is sufficient for values up to 200.
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_untouchable_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Reachability table: reachable[n]=1 means n = s(m) for some m */
static uint8_t reachable[201];

/* Sum of proper divisors of m */
static uint32_t proper_div_sum(uint32_t m)
{
    if (m <= 1u) return 0u;
    uint32_t s = 1u;
    for (uint32_t d = 2u; d * d <= m; d++) {
        if (m % d == 0u) {
            s += d;
            if (d != m / d) s += m / d;
        }
    }
    return s;
}

void _start(void)
{
    uint32_t n_tests = 199u;

    /* Sieve s(m) for m = 2..50000; mark reachable[s(m)] if s(m) <= 200 */
    for (uint32_t i = 0u; i <= 200u; i++) reachable[i] = 0u;

    for (uint32_t m = 2u; m <= 50000u; m++) {
        uint32_t sv = proper_div_sum(m);
        if (sv >= 2u && sv <= 200u) {
            reachable[sv] = 1u;
        }
    }

    /* Count untouchable numbers in [2..n_tests+1] */
    uint32_t count = 0u;
    uint32_t usum  = 0u;
    for (uint32_t n = 2u; n <= n_tests + 1u; n++) {
        if (!reachable[n]) {
            count++;
            usum += n;
        }
    }

    /* count=10, sum=983
     * metric_a = 10 & 0xFF = 0x0A
     * metric_b = 983 % 251  = 230 = 0xE6
     * g_result = (199<<16)|(10<<8)|230 = 0x00C70AE6 */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = usum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
