/* test_copeland_erdos.c
 * Purpose   : Build the Copeland-Erdos constant digit sequence
 * Algorithm : Concatenate the decimal digits of consecutive primes:
 *             2, 3, 5, 7, 11, 13, 17, 19, 23, 29, ...
 *             forming the irrational constant 0.2357111317192329...
 *             Count total digits and even digits in the first 10 primes.
 * Input     : first 10 primes: 2,3,5,7,11,13,17,19,23,29
 * Expected  : digit sequence = [2,3,5,7,1,1,1,3,1,7,1,9,2,3,2,9]
 *             n_primes = 10
 *             total_digits = 16
 *             even_count = 3   (digits 2, 2, 2 at positions 0, 12, 14)
 * g_result  = (n_primes<<16) | (total_digits<<8) | even_count
 *           = (10<<16) | (16<<8) | 3 = 0x0A1003
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* Small prime list: first 10 primes */
static const uint32_t ce_primes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29};
#define CE_N_PRIMES 10

/* Count decimal digits of a positive integer */
static uint32_t digit_count(uint32_t n) {
    if (n < 10) return 1;
    if (n < 100) return 2;
    if (n < 1000) return 3;
    return 4;
}

/* Extract k-th digit (0=most significant) of n */
static uint32_t get_digit(uint32_t n, uint32_t k, uint32_t total_d) {
    /* divide n by 10^(total_d-1-k) */
    uint32_t divisor = 1;
    uint32_t i;
    for (i = 0; i < total_d - 1 - k; i++) divisor *= 10;
    return (n / divisor) % 10;
}

void _start(void) {
    uint32_t n_primes = CE_N_PRIMES;
    uint32_t total_digits = 0;
    uint32_t even_count = 0;
    uint32_t pi;

    for (pi = 0; pi < n_primes; pi++) {
        uint32_t p = ce_primes[pi];
        uint32_t nd = digit_count(p);
        total_digits += nd;
        uint32_t di;
        for (di = 0; di < nd; di++) {
            uint32_t d = get_digit(p, di, nd);
            if ((d & 1u) == 0) {  /* even digit */
                even_count++;
            }
        }
    }

    /* n_primes=10, total_digits=16, even_count=3 => 0x0A1003 */
    g_result = (n_primes << 16) | (total_digits << 8) | even_count;
    while (1) {}
}
