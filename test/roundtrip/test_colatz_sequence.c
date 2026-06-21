/* test_colatz_sequence.c
 * Collatz (3n+1) sequence: for n > 1, apply n/2 if even, 3n+1 if odd,
 * until reaching 1.  The "stopping time" is the number of steps taken.
 *
 * Computes stopping times for n = 1..12, verifies against known values,
 * accumulates XOR of stopping times, and packs metrics into g_result.
 *
 * Known stopping times: 0,1,7,2,5,8,16,3,19,6,14,9
 *   (for n=1,2,...,12)
 *
 * All arithmetic 32-bit (no 64-bit intermediates).
 */
#include <stdint.h>

volatile uint32_t g_result;

#define COLATZ_START 1u
#define COLATZ_END   12u
#define COLATZ_COUNT (COLATZ_END - COLATZ_START + 1u)

static uint32_t colatz_steps(uint32_t n)
{
    uint32_t steps = 0u;
    while (n != 1u) {
        if (n & 1u)
            n = 3u * n + 1u;
        else
            n >>= 1u;
        steps++;
    }
    return steps;
}

static void run_colatz_sequence(void)
{
    /* Known stopping times for n=1..12 */
    uint32_t known[COLATZ_COUNT] = {0u, 1u, 7u, 2u, 5u, 8u, 16u, 3u, 19u, 6u, 14u, 9u};

    uint32_t n_tests = COLATZ_COUNT;
    uint32_t match_count = 0u;
    uint32_t xor_acc = 0u;

    for (uint32_t i = 0u; i < n_tests; i++) {
        uint32_t s = colatz_steps(COLATZ_START + i);
        xor_acc ^= s;
        if (s == known[i]) match_count++;
    }

    uint32_t metric_a = match_count & 0xFFu;          /* 0x0C = 12 if all match */
    uint32_t metric_b = (xor_acc ^ (xor_acc >> 16)) & 0xFFu;
    if (metric_a == 0u) metric_a = 0x33u;
    if (metric_b == 0u) metric_b = 0x4Au;
    if (metric_a == metric_b) metric_b ^= 0x1Bu;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void)
{
    run_colatz_sequence();
    while (1) {}
}
