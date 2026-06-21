/* test_pell_lucas.c — Pell-Lucas (companion Pell) sequence (32-bit, no libc)
 *
 * The Pell-Lucas (or companion Pell) sequence Q is defined by:
 *   Q(0) = 2,  Q(1) = 2,  Q(n) = 2*Q(n-1) + Q(n-2)  for n >= 2
 *
 * Values: 2,2,6,14,34,82,198,478,1154,2786,6726,...
 *
 * We compute Q(0)..Q(10) (11 terms), then:
 *   n_tests  = 11                            (count of terms)
 *   metric_a = sum(Q(0..10)) % 251           = 11482 % 251 = 187 = 0xBB
 *   metric_b = XOR of low bytes Q(0..10)     = 0x46 = 70
 *
 * g_result = (0x0B << 16) | (0xBB << 8) | 0x46 = 0x0BBB46
 * All bytes non-zero and distinct: 0x0B, 0xBB, 0x46 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

static void test_pell_lucas(void) {
    uint32_t q_prev2 = 2; /* Q(0) */
    uint32_t q_prev1 = 2; /* Q(1) */
    uint32_t q_cur;

    uint32_t term_sum = q_prev2 + q_prev1; /* Q(0) + Q(1) */
    uint32_t xor_acc  = (q_prev2 & 0xFFu) ^ (q_prev1 & 0xFFu);
    uint32_t i;
    for (i = 2; i <= 10; i++) {
        q_cur    = 2u * q_prev1 + q_prev2;
        term_sum += q_cur;
        xor_acc  ^= (q_cur & 0xFFu);
        q_prev2  = q_prev1;
        q_prev1  = q_cur;
    }
    /* term_sum = 11482, xor_acc = 0x46 */

    uint32_t n_tests  = 11u;
    uint32_t metric_a = term_sum % 251u;   /* 187 = 0xBB */
    uint32_t metric_b = xor_acc & 0xFFu;  /* 70  = 0x46 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    test_pell_lucas();
    while (1) {}
}
