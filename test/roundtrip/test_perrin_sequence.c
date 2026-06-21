/* test_perrin_sequence.c — Perrin sequence (32-bit, no libc)
 *
 * The Perrin sequence is defined by:
 *   P(0) = 3,  P(1) = 0,  P(2) = 2,  P(n) = P(n-2) + P(n-3)  for n >= 3
 *
 * Values: 3,0,2,3,2,5,5,7,10,12,17,22,29,...
 * Note: Perrin numbers have the property that if p is prime, p | P(p).
 *
 * We compute P(0)..P(12) (13 terms), then:
 *   n_tests  = 13                             (count of terms)
 *   metric_a = sum(P(0..12)) % 251            = 117 % 251 = 117 = 0x75
 *   metric_b = XOR of low bytes P(0..12)      = 0x1B = 27
 *
 * g_result = (0x0D << 16) | (0x75 << 8) | 0x1B = 0x0D751B
 * All bytes non-zero and distinct: 0x0D, 0x75, 0x1B ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

static void test_perrin_sequence(void) {
    /* P(0), P(1), P(2) initial values */
    uint32_t p[13];
    p[0] = 3;
    p[1] = 0;
    p[2] = 2;

    uint32_t i;
    for (i = 3; i < 13; i++) {
        p[i] = p[i - 2] + p[i - 3];
    }

    uint32_t term_sum = 0;
    uint32_t xor_acc  = 0;
    for (i = 0; i < 13; i++) {
        term_sum += p[i];
        xor_acc  ^= (p[i] & 0xFFu);
    }
    /* term_sum = 117, xor_acc = 0x1B */

    uint32_t n_tests  = 13u;
    uint32_t metric_a = term_sum % 251u;   /* 117 = 0x75 */
    uint32_t metric_b = xor_acc & 0xFFu;  /* 27  = 0x1B */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    test_perrin_sequence();
    while (1) {}
}
