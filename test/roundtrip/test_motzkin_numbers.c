/* test_motzkin_numbers.c
 * Motzkin numbers: M(n) = number of ways to draw non-crossing chords
 * on a circle with n points (also paths on a line that don't go below 0).
 * Recurrence: M(0)=1, M(1)=1,
 *   M(n) = M(n-1) + sum_{k=0}^{n-2} M(k)*M(n-2-k)
 * Equivalently: M(n) = ((2n+2)*M(n-1) + 3*M(n-2)) / (n+3)   [integer]
 * Use the simpler recurrence sum form (all 32-bit).
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MMAX 16

static uint32_t motzkin(uint32_t n) {
    uint32_t m[MMAX];
    uint32_t i, k;
    m[0] = 1;
    if (n == 0) return 1;
    m[1] = 1;
    if (n == 1) return 1;
    for (i = 2; i <= n; i++) {
        uint32_t s = m[i-1];
        for (k = 0; k <= i-2; k++) {
            s += m[k] * m[i-2-k];
        }
        m[i] = s;
    }
    return m[n];
}

static uint32_t motzkin_xor_check(void) {
    /* XOR M(1)..M(9) for a fingerprint */
    uint32_t x = 0;
    uint32_t i;
    for (i = 1; i <= 9; i++) {
        x ^= motzkin(i);
    }
    return x & 0xFF;
}

static void run_motzkin(void) {
    /* M(6)=51=0x33, M(7)=127=0x7F */
    uint32_t m6 = motzkin(6);    /* 51  */
    uint32_t m7 = motzkin(7);    /* 127 */
    uint32_t n_tests = 7;        /* compute M(1)..M(7) */
    uint32_t metric_a = m6 & 0xFF;          /* 0x33 */
    uint32_t metric_b = motzkin_xor_check();/* 0x?? */
    (void)m7;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    run_motzkin();
    while (1) {}
}
