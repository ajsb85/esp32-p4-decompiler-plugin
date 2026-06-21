/* test_burnside_polya_extended.c
 * Extended Burnside/Polya enumeration: count distinct necklaces of length N
 * with K colors using Burnside's lemma over the cyclic group Z_N.
 *
 * |Fix(r)| = K^gcd(r,N) for rotation r in Z_N.
 * Distinct necklaces = (1/N) * sum_{r=0}^{N-1} K^gcd(r,N)
 * (multiplied by N before dividing to keep integer arithmetic).
 *
 * Test cases: (N=4,K=3) -> 24, (N=6,K=2) -> 14, (N=5,K=3) -> 51,
 *             (N=3,K=4) -> 24, (N=8,K=2) -> 36.
 *
 * All arithmetic 32-bit.
 */
#include <stdint.h>

volatile uint32_t g_result;

static uint32_t gcd32(uint32_t a, uint32_t b)
{
    while (b) { uint32_t t = b; b = a % b; a = t; }
    return a;
}

static uint32_t pow32(uint32_t base, uint32_t exp)
{
    uint32_t result = 1u;
    while (exp > 0u) {
        if (exp & 1u) result *= base;
        base *= base;
        exp >>= 1u;
    }
    return result;
}

/* Count distinct necklaces: returns N * answer (sum of Fix(r)) */
static uint32_t burnside_necklace(uint32_t n, uint32_t k)
{
    uint32_t total = 0u;
    for (uint32_t r = 0u; r < n; r++) {
        total += pow32(k, gcd32(r, n));
    }
    return total / n;   /* exact integer division */
}

static void run_burnside_polya_extended(void)
{
    /* Test cases: (n, k, expected) */
    uint32_t ns[5]       = {4u, 6u, 5u, 3u, 8u};
    uint32_t ks[5]       = {3u, 2u, 3u, 4u, 2u};
    uint32_t expected[5] = {24u, 14u, 51u, 24u, 36u};

    uint32_t n_tests = 5u;
    uint32_t match_count = 0u;
    uint32_t xor_acc = 0u;

    for (uint32_t i = 0u; i < n_tests; i++) {
        uint32_t got = burnside_necklace(ns[i], ks[i]);
        xor_acc ^= got;
        if (got == expected[i]) match_count++;
    }

    uint32_t metric_a = match_count & 0xFFu;          /* 0x05 if all pass */
    uint32_t metric_b = (xor_acc ^ (xor_acc >> 16)) & 0xFFu;
    if (metric_a == 0u) metric_a = 0x3Au;
    if (metric_b == 0u) metric_b = 0x27u;
    if (metric_a == metric_b) metric_b ^= 0x19u;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void)
{
    run_burnside_polya_extended();
    while (1) {}
}
