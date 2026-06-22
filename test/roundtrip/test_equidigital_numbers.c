/* test_equidigital_numbers.c
 * Equidigital numbers: positive integers whose prime factorization (with
 * exponents written explicitly when > 1) uses exactly the same number of
 * digits as the number itself.
 * E.g. 1 is equidigital (trivially), 2 = "2" (1 digit = 1 digit),
 *      10 = 2*5 → "25" (2 digits) = "10" (2 digits) → equidigital.
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_equidigital_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

static uint32_t digit_count(uint32_t n)
{
    if (n == 0u) return 1u;
    uint32_t d = 0u;
    while (n > 0u) { n /= 10u; d++; }
    return d;
}

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

static uint32_t is_equidigital(uint32_t n)
{
    if (n < 2u) return 0u;
    return (factorization_digits(n) == digit_count(n)) ? 1u : 0u;
}

void _start(void)
{
    /* Count equidigital numbers in [2..499] and accumulate sum */
    uint32_t n_tests = 499u;
    uint32_t count   = 0u;
    uint32_t esum    = 0u;

    for (uint32_t n = 2u; n <= n_tests; n++) {
        if (is_equidigital(n)) {
            count++;
            esum += n;
        }
    }

    /* metric_a = count & 0xFF, metric_b = esum % 251u */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = esum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
