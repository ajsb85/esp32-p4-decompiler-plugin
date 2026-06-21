/* test_sum_of_squares.c
 * Purpose   : Determine minimum number of perfect squares needed per integer
 * Algorithm : By Legendre's three-square theorem and related results:
 *             - 1 square  if n is a perfect square
 *             - 4 squares if n = 4^a * (8b+7) for some a,b >= 0 (Legendre)
 *             - 2 squares if expressible as sum of 2 squares but not 1
 *             - 3 squares otherwise
 *             Test n = 1..20, count how many need exactly 1 square (c1)
 *             and exactly 4 squares (c4).
 * Input     : n = 1..20, n_tests = 20
 * Expected  : c1 = 4  (n=1,4,9,16 are perfect squares)
 *             c4 = 2  (n=7,15 satisfy Legendre's condition)
 *             g_result = (n_tests<<16) | (c1<<8) | c4
 *                      = (20<<16) | (4<<8) | 2 = 0x140402
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* Integer square root (floor) */
static uint32_t isqrt32(uint32_t n) {
    if (n == 0) return 0;
    uint32_t x = n;
    uint32_t y = (x + 1) >> 1;
    while (y < x) {
        x = y;
        y = (x + n / x) >> 1;
    }
    return x;
}

/* Check if n is a perfect square */
static uint32_t is_perfect_square(uint32_t n) {
    uint32_t s = isqrt32(n);
    return s * s == n;
}

/* Check if n is expressible as a^2 + b^2 */
static uint32_t is_sum_of_two_squares(uint32_t n) {
    uint32_t a;
    for (a = 0; a * a <= n; a++) {
        uint32_t rem = n - a * a;
        if (is_perfect_square(rem)) return 1;
    }
    return 0;
}

/* Check if n requires 4 squares: n = 4^a * (8b+7) */
static uint32_t needs_four_squares(uint32_t n) {
    while (n % 4 == 0) n >>= 2;
    return (n % 8) == 7;
}

/* Return minimum number of squares summing to n */
static uint32_t min_squares(uint32_t n) {
    if (is_perfect_square(n)) return 1;
    if (needs_four_squares(n)) return 4;
    if (is_sum_of_two_squares(n)) return 2;
    return 3;
}

void _start(void) {
    uint32_t n_tests = 20;
    uint32_t c1 = 0;  /* count needing exactly 1 square */
    uint32_t c4 = 0;  /* count needing exactly 4 squares */
    uint32_t i;

    for (i = 1; i <= n_tests; i++) {
        uint32_t ms = min_squares(i);
        if (ms == 1) c1++;
        if (ms == 4) c4++;
    }

    /* n_tests=20, c1=4, c4=2 => 0x140402 */
    g_result = (n_tests << 16) | (c1 << 8) | c4;
    while (1) {}
}
