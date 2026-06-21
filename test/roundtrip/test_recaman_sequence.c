/* test_recaman_sequence.c — Recaman's sequence (32-bit, no libc)
 *
 * Recaman's sequence (OEIS A005132):
 *   a(0) = 0
 *   a(n) = a(n-1) - n  if positive and not already in sequence
 *   a(n) = a(n-1) + n  otherwise
 *
 * Values a(0)..a(14): 0,1,3,6,2,7,13,20,12,21,11,22,10,23,9
 *
 * We mark visited values in a boolean array (max value bounded by ~N^2).
 * We compute a(0)..a(14) (15 terms), then:
 *   n_tests  = 15                          = 0x0F
 *   metric_a = sum(a(0..14)) % 251         = 160 % 251 = 160 = 0xA0
 *   metric_b = XOR of low bytes a(0..14)  = 0x08 = 8
 *
 * g_result = (0x0F << 16) | (0xA0 << 8) | 0x08 = 0x0FA008
 * All bytes non-zero and distinct: 0x0F, 0xA0, 0x08 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Max possible value for 15 terms: a(n) <= a(n-1)+n <= ... roughly N*(N+1)/2 = ~120 */
#define RECAMAN_N  15
#define SEEN_SIZE  200

static void test_recaman_sequence(void) {
    uint32_t a[RECAMAN_N];
    uint8_t  seen[SEEN_SIZE];
    uint32_t i;

    for (i = 0u; i < SEEN_SIZE; i++) {
        seen[i] = 0u;
    }

    a[0] = 0u;
    seen[0] = 1u;

    for (i = 1u; i < RECAMAN_N; i++) {
        uint32_t sub = a[i - 1u] - i;  /* unsigned: wraps if negative */
        /* Check: sub > 0 means no underflow, and sub < SEEN_SIZE */
        if (a[i - 1u] > i && sub < SEEN_SIZE && !seen[sub]) {
            a[i] = sub;
        } else {
            a[i] = a[i - 1u] + i;
        }
        if (a[i] < SEEN_SIZE) {
            seen[a[i]] = 1u;
        }
    }

    uint32_t term_sum = 0u;
    uint32_t xor_acc  = 0u;
    for (i = 0u; i < RECAMAN_N; i++) {
        term_sum += a[i];
        xor_acc  ^= (a[i] & 0xFFu);
    }
    /* term_sum = 160, xor_acc = 0x08 */

    uint32_t n_tests  = 15u;
    uint32_t metric_a = term_sum % 251u;   /* 160 = 0xA0 */
    uint32_t metric_b = xor_acc & 0xFFu;  /* 8   = 0x08 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    test_recaman_sequence();
    while (1) {}
}
