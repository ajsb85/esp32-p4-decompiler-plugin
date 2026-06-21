/* test_automorphic_numbers.c
 * Automorphic numbers: n^2 ends in n (e.g. 5^2=25, 6^2=36, 25^2=625, 76^2=5776)
 * Detect automorphic numbers up to a bound and compute metrics.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_automorphic_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Return 1 if n is an automorphic number, 0 otherwise.
 * An automorphic number n satisfies: (n*n) % (10^d) == n
 * where d is the number of decimal digits of n.
 */
static int is_automorphic(uint32_t n) {
    if (n == 0) return 1; /* 0^2=0 ends in 0 */
    uint32_t sq = n * n;
    uint32_t mod = 1;
    uint32_t tmp = n;
    /* compute 10^(number of digits in n) */
    while (tmp > 0) {
        mod *= 10;
        tmp /= 10;
    }
    return (sq % mod) == n;
}

/* Count automorphic numbers in [1..limit] and sum their digit counts */
static void automorphic_compute(uint32_t limit,
                                uint32_t *out_count,
                                uint32_t *out_digit_sum) {
    uint32_t count = 0;
    uint32_t digit_sum = 0;
    uint32_t i;
    for (i = 1; i <= limit; i++) {
        if (is_automorphic(i)) {
            count++;
            /* count digits of i */
            uint32_t tmp2 = i;
            uint32_t d = 0;
            while (tmp2 > 0) { d++; tmp2 /= 10; }
            digit_sum += d;
        }
    }
    *out_count = count;
    *out_digit_sum = digit_sum;
}

void _start(void) {
    /* Test with limit=10000 */
    uint32_t count = 0, digit_sum = 0;
    automorphic_compute(10000, &count, &digit_sum);

    /* n_tests=7, metric_a = count & 0xFF, metric_b = digit_sum & 0xFF */
    uint32_t n_tests  = 7;
    uint32_t metric_a = count & 0xFF;         /* number of automorphic numbers found */
    uint32_t metric_b = digit_sum & 0xFF;     /* total digit count of found numbers */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;

    while (1) {}
}
