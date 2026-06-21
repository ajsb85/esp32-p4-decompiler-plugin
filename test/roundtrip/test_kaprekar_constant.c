/* test_kaprekar_constant.c — Kaprekar's constant (32-bit, no libc)
 *
 * Kaprekar's routine: for any 4-digit number (not a repdigit), sorting digits
 * descending and ascending then subtracting eventually converges to 6174.
 *
 * Algorithm:
 *   big   = digits arranged largest-first
 *   small = digits arranged smallest-first
 *   next  = big - small
 * Repeat until result == 6174.
 *
 * We test 10 starting values and count steps to convergence.
 * Starting values: 1234,2345,3456,4567,5678,6789,1357,2468,9753,8765
 * Steps:              3,   3,   3,   3,   3,   3,   1,   1,   1,   3
 *
 *   n_tests  = 10                           = 0x0A
 *   metric_a = sum_of_steps & 0xFF          = 24 = 0x18
 *   metric_b = XOR of step counts & 0xFF   = 2  = 0x02
 *
 * g_result = (0x0A << 16) | (0x18 << 8) | 0x02 = 0x0A1802
 * All bytes non-zero and distinct: 0x0A, 0x18, 0x02 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Sort 4 decimal digits of n into d[0..3] ascending */
static void extract_digits(uint32_t n, uint32_t d[4]) {
    uint32_t i, j, tmp;
    for (i = 0u; i < 4u; i++) {
        d[i] = n % 10u;
        n /= 10u;
    }
    /* bubble sort ascending */
    for (i = 0u; i < 3u; i++) {
        for (j = 0u; j < 3u - i; j++) {
            if (d[j] > d[j + 1u]) {
                tmp = d[j]; d[j] = d[j + 1u]; d[j + 1u] = tmp;
            }
        }
    }
}

static uint32_t kaprekar_steps(uint32_t n) {
    uint32_t d[4];
    uint32_t steps = 0u;
    while (n != 6174u && steps < 7u) {
        extract_digits(n, d);
        uint32_t big   = d[3]*1000u + d[2]*100u + d[1]*10u + d[0];
        uint32_t small = d[0]*1000u + d[1]*100u + d[2]*10u + d[3];
        n = big - small;
        steps++;
        if (n == 0u) { steps = 7u; break; }
    }
    return steps;
}

static void test_kaprekar_constant(void) {
    static const uint32_t starts[10] = {
        1234u, 2345u, 3456u, 4567u, 5678u,
        6789u, 1357u, 2468u, 9753u, 8765u
    };
    uint32_t step_sum = 0u;
    uint32_t xor_acc  = 0u;
    uint32_t i;
    for (i = 0u; i < 10u; i++) {
        uint32_t s = kaprekar_steps(starts[i]);
        step_sum += s;
        xor_acc  ^= (s & 0xFFu);
    }
    /* step_sum = 24, xor_acc = 0x02 */

    uint32_t n_tests  = 10u;
    uint32_t metric_a = step_sum & 0xFFu;  /* 24 = 0x18 */
    uint32_t metric_b = xor_acc & 0xFFu;  /* 2  = 0x02 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    test_kaprekar_constant();
    while (1) {}
}
