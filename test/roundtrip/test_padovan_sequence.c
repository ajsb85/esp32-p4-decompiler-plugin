/* test_padovan_sequence.c
 * Padovan sequence: P(n) = P(n-2) + P(n-3), P(0)=P(1)=P(2)=1.
 * Values: 1,1,1,2,2,3,4,5,7,9,12,16,21,28,37,...
 *
 * Computes first 15 Padovan numbers, verifies against known table,
 * accumulates XOR, and packs metrics into g_result.
 * All arithmetic 32-bit.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PAD_N 15u

static uint32_t pad_table[PAD_N];

static void compute_padovan(void)
{
    pad_table[0] = 1u;
    pad_table[1] = 1u;
    pad_table[2] = 1u;
    for (uint32_t i = 3u; i < PAD_N; i++) {
        pad_table[i] = pad_table[i-2] + pad_table[i-3];
    }
}

static void run_padovan_sequence(void)
{
    compute_padovan();

    /* Known Padovan values P(0)..P(14) */
    uint32_t known[PAD_N] = {
        1u, 1u, 1u, 2u, 2u, 3u, 4u, 5u, 7u, 9u, 12u, 16u, 21u, 28u, 37u
    };

    uint32_t n_tests = PAD_N;
    uint32_t match_count = 0u;
    uint32_t xor_acc = 0u;

    for (uint32_t i = 0u; i < n_tests; i++) {
        xor_acc ^= pad_table[i];
        if (pad_table[i] == known[i]) match_count++;
    }

    uint32_t metric_a = match_count & 0xFFu;          /* 0x0F = 15 if all match */
    uint32_t metric_b = (xor_acc ^ (xor_acc >> 16)) & 0xFFu;
    if (metric_a == 0u) metric_a = 0x2Eu;
    if (metric_b == 0u) metric_b = 0x41u;
    if (metric_a == metric_b) metric_b ^= 0x17u;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void)
{
    run_padovan_sequence();
    while (1) {}
}
