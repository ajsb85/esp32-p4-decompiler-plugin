/* test_digital_root.c
 * Digital root: repeatedly sum the digits of n until a single digit.
 * Formula: dr(0)=0, dr(n)=1+(n-1)%9  (base-10).
 * Also computes the additive persistence: how many times digit-sum is needed.
 * All arithmetic is 32-bit.
 */
#include <stdint.h>

volatile uint32_t g_result;

static uint32_t digit_sum(uint32_t n) {
    uint32_t s = 0;
    while (n > 0) {
        s += n % 10;
        n /= 10;
    }
    return s;
}

static uint32_t digital_root(uint32_t n) {
    if (n == 0) return 0;
    return 1 + (n - 1) % 9;
}

static uint32_t additive_persistence(uint32_t n) {
    uint32_t steps = 0;
    while (n >= 10) {
        n = digit_sum(n);
        steps++;
    }
    return steps;
}

static void run_digital_root(void) {
    /* Batch: compute digital_root and persistence for several numbers */
    uint32_t test_vals[9] = {493, 942, 999, 1234, 9999, 77777, 199, 100, 8675309};
    uint32_t i;
    uint32_t dr_xor = 0;
    uint32_t persist_sum = 0;
    uint32_t n_tests = 9;

    for (i = 0; i < n_tests; i++) {
        uint32_t v = test_vals[i];
        dr_xor ^= digital_root(v);
        persist_sum += additive_persistence(v);
    }

    /* dr_xor and persist_sum are small; pack them */
    uint32_t metric_a = dr_xor & 0xFF;
    uint32_t metric_b = persist_sum & 0xFF;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    run_digital_root();
    while (1) {}
}
