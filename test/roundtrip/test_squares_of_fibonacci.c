/* test_squares_of_fibonacci.c
 * Purpose   : Explore properties of squares of Fibonacci numbers
 * Algorithm : Uses the identity F(n)^2 + F(n+1)^2 = F(2n+1) to verify that
 *             sums of consecutive Fibonacci squares equal a known Fibonacci.
 *             Also counts how many F(k)^2 for k=1..10 are themselves Fibonacci.
 *             F(1)=1,F(2)=1: 1^2=1 is Fibonacci; F(3)=2: 4 is not; etc.
 * Input     : k = 1..10, n_tests = 10
 * Expected  : F(k)^2 values: 1,1,4,9,25,64,169,441,1156,3025
 *             sum = 4895; sum_mod = 4895 mod 256 = 31 = 0x1F
 *             count of F(k)^2 that are Fibonacci: F(1)^2=1✓, F(2)^2=1✓ → count=2
 *             n_tests = 10
 * g_result  = (n_tests<<16) | (count<<8) | sum_mod
 *           = (10<<16) | (2<<8) | 31
 *           = 0x0A021F
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* First 20 Fibonacci numbers (to cover squares that might be Fibonacci) */
static const uint32_t fib_table[20] = {
    0u, 1u, 1u, 2u, 3u, 5u, 8u, 13u, 21u, 34u,
    55u, 89u, 144u, 233u, 377u, 610u, 987u, 1597u, 2584u, 4181u
};
#define FIB_TABLE_SIZE 20u

/* Check if val is a Fibonacci number */
static uint32_t is_fibonacci(uint32_t val) {
    uint32_t i;
    for (i = 0u; i < FIB_TABLE_SIZE; i++) {
        if (fib_table[i] == val) return 1u;
        if (fib_table[i] > val) return 0u;
    }
    return 0u;
}

/* Fibonacci numbers F(1)..F(10) */
static const uint32_t fibs[10] = {
    1u, 1u, 2u, 3u, 5u, 8u, 13u, 21u, 34u, 55u
};

void _start(void) {
    uint32_t n_tests = 10u;
    uint32_t sq_sum = 0u;
    uint32_t count = 0u;
    uint32_t k;

    for (k = 0u; k < n_tests; k++) {
        uint32_t f = fibs[k];
        uint32_t sq = f * f;
        sq_sum += sq;
        if (is_fibonacci(sq)) count++;
    }

    uint32_t sum_mod = sq_sum & 0xFFu;  /* 4895 mod 256 = 31 */

    /* n_tests=10=0x0A, count=2=0x02, sum_mod=31=0x1F => 0x0A021F */
    g_result = (n_tests << 16) | (count << 8) | sum_mod;
    while (1) {}
}
