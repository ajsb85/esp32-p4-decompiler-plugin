/* test_integer_sqrt_newton.c
 * Purpose   : Validate integer square root via Newton's method (Heron's method)
 * Algorithm : Newton iteration for floor(sqrt(n)):
 *               x_{k+1} = (x_k + n/x_k) / 2
 *             Start from x0 = n, iterate until convergence (x_{k+1} >= x_k).
 *             The final result is floor(sqrt(n)).
 * Input     : n = 1..20 (n_tests=20)
 * Expected  : sum of floor(sqrt(i)) for i=1..20 = 54
 *             count of perfect squares in [1,20] = {1,4,9,16} => count_perfect=4
 *             n_tests = 20
 * g_result  = (n_tests<<16) | (count_perfect<<8) | (sum & 0xFF)
 *           = (20<<16) | (4<<8) | 54 = 0x140436
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

static uint32_t isqrt_newton(uint32_t n) {
    if (n == 0) return 0;
    if (n == 1) return 1;
    uint32_t x = n;
    uint32_t y = (x + 1) >> 1;
    while (y < x) {
        x = y;
        y = (x + n / x) >> 1;
    }
    return x;
}

void _start(void) {
    uint32_t n_tests = 20;
    uint32_t sum_roots = 0;
    uint32_t count_perfect = 0;

    for (uint32_t i = 1; i <= n_tests; i++) {
        uint32_t r = isqrt_newton(i);
        sum_roots += r;
        if (r * r == i) count_perfect++;
    }

    /* n_tests=20, count_perfect=4, sum_roots=54 => 0x140436 */
    g_result = (n_tests << 16) | (count_perfect << 8) | (sum_roots & 0xFF);
    while (1) {}
}
