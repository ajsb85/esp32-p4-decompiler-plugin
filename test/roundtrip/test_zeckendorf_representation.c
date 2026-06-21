/* test_zeckendorf_representation.c
 * Purpose   : Compute Zeckendorf representation of integers 1..15
 * Algorithm : Zeckendorf's theorem: every positive integer has a unique
 *             representation as a sum of non-consecutive Fibonacci numbers.
 *             Greedy algorithm: repeatedly subtract the largest Fibonacci
 *             number <= n.  Count the number of Fibonacci terms used.
 * Input     : n = 1..15 (n_tests=15)
 * Expected  : sum of term-counts for n=1..15:
 *               n=1:F(1)=1(1t), n=2:F(2)=1t, n=3:F(3)=1t, n=4:F(3)+F(1)=2t,
 *               n=5:1t, n=6:2t, n=7:2t, n=8:1t, n=9:2t, n=10:2t, n=11:2t,
 *               n=12:3t, n=13:1t, n=14:2t, n=15:2t  => sum_bits=25, max_bits=3
 *             n_tests = 15
 * g_result  = (n_tests<<16) | (sum_bits<<8) | max_bits
 *           = (15<<16) | (25<<8) | 3 = 0x0F1903
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* Fibonacci numbers up to 1000 (well past 15) */
static const uint32_t zeck_fibs[] = {
    1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987
};
#define ZECK_NFIBS 15

static uint32_t zeckendorf_count(uint32_t n) {
    uint32_t count = 0;
    /* find the largest Fibonacci <= n greedily */
    int i = ZECK_NFIBS - 1;
    while (n > 0 && i >= 0) {
        while (i >= 0 && zeck_fibs[i] > n) i--;
        if (i < 0) break;
        n -= zeck_fibs[i];
        count++;
        i--;  /* skip adjacent Fibonacci to ensure non-consecutive */
    }
    return count;
}

void _start(void) {
    uint32_t n_tests = 15;
    uint32_t sum_bits = 0;
    uint32_t max_bits = 0;

    for (uint32_t i = 1; i <= n_tests; i++) {
        uint32_t b = zeckendorf_count(i);
        sum_bits += b;
        if (b > max_bits) max_bits = b;
    }

    /* n_tests=15, sum_bits=25, max_bits=3 => 0x0F1903 */
    g_result = (n_tests << 16) | (sum_bits << 8) | max_bits;
    while (1) {}
}
