/* SPDX-License-Identifier: Apache-2.0
 * Extended round-trip test: Galois LFSR + Fibonacci LFSR.
 *
 * Exercises: shift-and-XOR feedback, mask constant, uint32_t right-shift,
 *            for-loop with fixed iteration count.
 *
 * Expected pattern detection: rng_lfsr (shift + xor + mask pattern)
 *
 * Galois LFSR — polynomial x^32+x^22+x^2+x^1+1 (taps 0x80200003):
 *   Start: 0xACE1u, run 32 steps.
 *
 * Fibonacci LFSR — taps at positions 32,22,2,1 (Galois equivalent):
 *   Start: 0xACE1u, run 32 steps.
 *
 * Both LFSRs starting from the same seed will produce the same maximal
 * sequence (different representation, same period). After 32 steps the
 * Galois state differs from the Fibonacci state, but both are correct.
 *
 * Expected:
 *   galois_state  after 32 steps: computed deterministically
 *   fib_state     after 32 steps: computed deterministically
 *   g_result = galois_state ^ fib_state  (validates both implementations)
 *              (if both are bug-free, the XOR is a known constant)
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Galois (external XOR) LFSR step: tap mask 0x80200003 */
static uint32_t galois_lfsr_step(uint32_t state) {
    uint32_t lsb = state & 1u;
    state >>= 1;
    if (lsb) state ^= 0x80200003u;
    return state;
}

/* Fibonacci (internal XOR) LFSR — taps at bits 31,21,1,0 (same polynomial) */
static uint32_t fibonacci_lfsr_step(uint32_t state) {
    uint32_t bit = ((state >> 31) ^ (state >> 21) ^ (state >> 1) ^ state) & 1u;
    return (state >> 1) | (bit << 31);
}

/* Run N steps and return final state */
static uint32_t run_galois(uint32_t seed, uint32_t steps) {
    for (uint32_t i = 0; i < steps; i++)
        seed = galois_lfsr_step(seed);
    return seed;
}

static uint32_t run_fibonacci(uint32_t seed, uint32_t steps) {
    for (uint32_t i = 0; i < steps; i++)
        seed = fibonacci_lfsr_step(seed);
    return seed;
}

/* Collect N output bits into a uint32_t word (LSB first) */
static uint32_t lfsr_collect_bits(uint32_t seed, uint32_t n_bits) {
    uint32_t out = 0;
    for (uint32_t i = 0; i < n_bits; i++) {
        out |= (seed & 1u) << i;
        seed = galois_lfsr_step(seed);
    }
    return out;
}

void _start(void) {
    uint32_t seed = 0x0000ACE1u;

    uint32_t gal32 = run_galois(seed, 32u);
    uint32_t fib32 = run_fibonacci(seed, 32u);

    /* Collect first 16 output bits from Galois LFSR */
    uint32_t bits16 = lfsr_collect_bits(seed, 16u);

    /* XOR of three deterministic values */
    g_result = gal32 ^ fib32 ^ bits16;

    for (;;);
}
