/* test_frugal_numbers.c
 * Frugal numbers: positive integers whose prime factorization (with exponents
 * written explicitly when > 1) uses strictly fewer digits than the number itself.
 * E.g. 125 = 5^3 → "53" (2 digits) < "125" (3 digits) → frugal.
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_frugal_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Count decimal digits of a positive integer */
static uint32_t digit_count(uint32_t n)
{
    if (n == 0u) return 1u;
    uint32_t d = 0u;
    while (n > 0u) { n /= 10u; d++; }
    return d;
}

/* Count digits in the prime factorization representation of n.
 * For each prime factor p with exponent e:
 *   - always count digits of p
 *   - if e > 1, also count digits of e
 */
static uint32_t factorization_digits(uint32_t n)
{
    uint32_t fd = 0u;
    uint32_t d = 2u;
    while (d * d <= n) {
        if (n % d == 0u) {
            uint32_t exp = 0u;
            while (n % d == 0u) { exp++; n /= d; }
            fd += digit_count(d);
            if (exp > 1u) fd += digit_count(exp);
        }
        d++;
    }
    if (n > 1u) fd += digit_count(n);
    return fd;
}

static uint32_t is_frugal(uint32_t n)
{
    if (n < 2u) return 0u;
    return (factorization_digits(n) < digit_count(n)) ? 1u : 0u;
}

void _start(void)
{
    /* Count frugal numbers in [2..499] and accumulate their sum */
    uint32_t n_tests  = 499u;
    uint32_t count    = 0u;
    uint32_t fsum     = 0u;

    for (uint32_t n = 2u; n <= n_tests; n++) {
        if (is_frugal(n)) {
            count++;
            fsum += n;
        }
    }

    /* Encode: n_tests=499 (0x1F3), count in [2..499]~15, fsum%251
     * Ensure all three bytes are non-zero and distinct.
     * metric_a = count & 0xFF, metric_b = fsum % 251u */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = fsum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
