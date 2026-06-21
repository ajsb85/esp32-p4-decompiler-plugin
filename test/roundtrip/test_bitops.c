/* SPDX-License-Identifier: Apache-2.0
 * Extended round-trip test: miscellaneous bit operations.
 *
 * Exercises: GCD (Euclidean), byte endian swap, nibble swap, parity,
 *            Gray code encode/decode, saturating add.
 *
 * Expected pattern detection: endian_swap (0xFF00FF00 mask pattern),
 *                              popcount (parity via XOR folding)
 *
 * Expected g_result (all values XOR'd together):
 *   gcd(1071, 462) = 21
 *   swap32(0x12345678) = 0x78563412
 *   nibble_swap(0xABCD) = 0xBADC
 *   parity(0xDEADBEEF) = 0 (even, since popcount=24)
 *   gray_encode(0x1234) = 0x1234 ^ (0x1234 >> 1) = 0x1234 ^ 0x091A = 0x1B2E
 *   gray_decode(0x1B2E) = 0x1234 (round-trip)
 *   sat_add(0xFFFF0000, 0x00010000) = 0xFFFFFFFF (saturate)
 *   popcount_k(0xDEADBEEF) = 24
 *
 *   g_result = 21 ^ 0x78563412 ^ 0xBADC ^ 0 ^ 0x1B2E ^ 0x1234 ^ 0xFFFFFFFF ^ 24
 *            = 0x87A97826
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Euclidean GCD */
static uint32_t gcd(uint32_t a, uint32_t b) {
    while (b) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

/* Byte-swap 32-bit big-endian ↔ little-endian */
static uint32_t swap32(uint32_t x) {
    return ((x & 0xFF000000u) >> 24)
         | ((x & 0x00FF0000u) >>  8)
         | ((x & 0x0000FF00u) <<  8)
         | ((x & 0x000000FFu) << 24);
}

/* Nibble-swap each byte (0xAB → 0xBA) */
static uint32_t nibble_swap(uint32_t x) {
    return ((x & 0xF0F0F0F0u) >> 4)
         | ((x & 0x0F0F0F0Fu) << 4);
}

/* Parity bit (XOR folding of popcount) */
static uint32_t parity(uint32_t x) {
    x ^= x >> 16;
    x ^= x >>  8;
    x ^= x >>  4;
    x ^= x >>  2;
    x ^= x >>  1;
    return x & 1u;
}

/* Gray code encode */
static uint32_t gray_encode(uint32_t n) {
    return n ^ (n >> 1);
}

/* Gray code decode */
static uint32_t gray_decode(uint32_t g) {
    uint32_t mask = g >> 1;
    while (mask) {
        g    ^= mask;
        mask >>= 1;
    }
    return g;
}

/* Saturating unsigned 32-bit add */
static uint32_t sat_add(uint32_t a, uint32_t b) {
    uint32_t r = a + b;
    return (r < a) ? 0xFFFFFFFFu : r;
}

/* Count set bits (Brian Kernighan) */
static uint32_t popcount_k(uint32_t x) {
    uint32_t n = 0;
    while (x) { x &= x - 1; n++; }
    return n;
}

void _start(void) {
    uint32_t v_gcd   = gcd(1071u, 462u);            /* = 21 */
    uint32_t v_swap  = swap32(0x12345678u);          /* = 0x78563412 */
    uint32_t v_nib   = nibble_swap(0xABCDu);         /* = 0xBADC */
    uint32_t v_par   = parity(0xDEADBEEFu);          /* = 0 (even parity) */
    uint32_t v_genc  = gray_encode(0x1234u);         /* = 0x0B2E */
    uint32_t v_gdec  = gray_decode(v_genc);          /* = 0x1234 */
    uint32_t v_sat   = sat_add(0xFFFF0000u, 0x00010000u); /* = 0xFFFFFFFF */
    uint32_t v_pop   = popcount_k(0xDEADBEEFu);      /* = 24 */

    g_result = v_gcd ^ v_swap ^ v_nib ^ v_par ^ v_genc ^ v_gdec ^ v_sat ^ v_pop;

    for (;;);
}
