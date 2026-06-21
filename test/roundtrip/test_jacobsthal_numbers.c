/* test_jacobsthal_numbers.c — Jacobsthal sequence (32-bit, no libc)
 *
 * The Jacobsthal sequence is defined by:
 *   J(0) = 0,  J(1) = 1,  J(n) = J(n-1) + 2*J(n-2)  for n >= 2
 *
 * Values: 0,1,1,3,5,11,21,43,85,171,341,683,1365,2731,...
 *
 * We compute J(1)..J(12), then:
 *   n_tests  = 12                          (number of terms)
 *   metric_a = sum(J(1..12)) % 251         = 2730 % 251 = 220 = 0xDC
 *   metric_b = XOR of low bytes J(1..12)   = 0x66
 *
 * g_result = (0x0C << 16) | (0xDC << 8) | 0x66 = 0x0CDC66
 * All bytes non-zero and distinct: 0x0C, 0xDC, 0x66 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

static void test_jacobsthal_numbers(void) {
    uint32_t j_prev2 = 0; /* J(0) */
    uint32_t j_prev1 = 1; /* J(1) */
    uint32_t j_cur;

    uint32_t term_sum = j_prev1; /* include J(1) */
    uint32_t xor_acc  = j_prev1 & 0xFFu;
    uint32_t i;
    for (i = 2; i <= 12; i++) {
        j_cur   = j_prev1 + 2u * j_prev2;
        term_sum += j_cur;
        xor_acc  ^= (j_cur & 0xFFu);
        j_prev2  = j_prev1;
        j_prev1  = j_cur;
    }
    /* term_sum = 2730, xor_acc = 0x66 */

    uint32_t n_tests  = 12u;
    uint32_t metric_a = term_sum % 251u;   /* 220 = 0xDC */
    uint32_t metric_b = xor_acc & 0xFFu;  /* 102 = 0x66 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    test_jacobsthal_numbers();
    while (1) {}
}
