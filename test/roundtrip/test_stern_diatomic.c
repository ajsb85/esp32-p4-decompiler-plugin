/* test_stern_diatomic.c — Stern's diatomic sequence (32-bit, no libc)
 *
 * Stern's diatomic sequence (also called fusc):
 *   s[0] = 0,  s[1] = 1
 *   s[2n]   = s[n]
 *   s[2n+1] = s[n] + s[n+1]
 *
 * Values for s[0..20]: 0,1,1,2,1,3,2,3,1,4,3,5,2,5,3,4,1,5,4,7,3
 *
 * We compute s[0..19] (20 terms) using a bottom-up fill, then:
 *   n_tests  = 20                          = 0x14
 *   metric_a = sum(s[0..19]) % 251         = 60 % 251 = 60 = 0x3C
 *   metric_b = XOR of low bytes s[0..19]  = 0x06 = 6
 *
 * g_result = (0x14 << 16) | (0x3C << 8) | 0x06 = 0x143C06
 * All bytes non-zero and distinct: 0x14, 0x3C, 0x06 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

static void test_stern_diatomic(void) {
    /* s[0..20] — we need s[10] to fill s[20]=s[10] and s[21]=s[10]+s[11] */
    uint32_t s[21];
    s[0] = 0u;
    s[1] = 1u;

    uint32_t i;
    for (i = 1u; i <= 10u; i++) {
        if (2u * i <= 20u) {
            s[2u * i] = s[i];
        }
        if (2u * i + 1u <= 20u) {
            s[2u * i + 1u] = s[i] + s[i + 1u];
        }
    }

    uint32_t term_sum = 0u;
    uint32_t xor_acc  = 0u;
    for (i = 0u; i < 20u; i++) {
        term_sum += s[i];
        xor_acc  ^= (s[i] & 0xFFu);
    }
    /* term_sum = 60, xor_acc = 0x06 */

    uint32_t n_tests  = 20u;
    uint32_t metric_a = term_sum % 251u;   /* 60 = 0x3C */
    uint32_t metric_b = xor_acc & 0xFFu;  /* 6  = 0x06 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    test_stern_diatomic();
    while (1) {}
}
