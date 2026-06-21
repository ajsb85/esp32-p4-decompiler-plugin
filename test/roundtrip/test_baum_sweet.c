/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Baum-Sweet sequence fixture.
 *
 * The Baum-Sweet sequence B(n) (n >= 0):
 *   B(n) = 1 if binary(n) contains no odd-length block of consecutive 0s,
 *           else 0.
 *   B(0) = 1 (empty representation: no odd-length zero blocks).
 *
 * Examples:
 *   B(0)=1 (0b0 → trailing zeros don't count, or: empty → 1)
 *   B(1)=1 (0b1 → no zero blocks)
 *   B(2)=0 (0b10 → one 0 in the middle, odd-length block → 0)
 *   B(3)=1 (0b11 → no zero blocks)
 *   B(4)=1 (0b100 → block of 2 zeros, even → 1)
 *   B(5)=0 (0b101 → block of 1 zero, odd → 0)
 *   B(6)=0 (0b110 → block of 1 zero at LSB, odd → 0)
 *   B(7)=1 (0b111 → no zero blocks)
 *
 * Distinctive decompiler idioms:
 *   1. Zero-run scanner: shift through bits counting run lengths
 *   2. Even/odd length test on each run: `if (run_len & 1) return 0`
 *   3. Outer loop over candidate n values
 *
 * Test: Compute B(0..31), count B(n)==1, XOR those indices.
 *
 * B[0..31] = {1,1,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,0,0,1,0,0,0,0,0,1,0,0,1,0,0,1}
 * Count = 13, XOR of indices = 0^1^3^4^7^9^12^15^16^19^25^28^31
 *       = 0^1=1, ^3=2, ^4=6, ^7=1, ^9=8, ^12=4, ^15=11, ^16=27, ^19=8, ^25=17, ^28=29, ^31=2
 * Actually XOR = 18 (verified by computation below)
 *
 * g_result = (32<<16)|(13<<8)|18 = 0x00200D12
 * Bytes: 0x20=32, 0x0D=13, 0x12=18 — all distinct and non-zero.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BS_N 32u

/* Scan n (from LSB to MSB, ignoring leading zeros) for odd-length 0-runs.
 * Return 1 if none found, else 0. */
static uint32_t baum_sweet(uint32_t n)
{
    if (n == 0u) return 1u;   /* convention: B(0)=1 */

    uint32_t tmp = n;
    uint32_t in_zero = 0u;
    uint32_t run_len = 0u;

    while (tmp > 0u) {
        uint32_t bit = tmp & 1u;
        tmp >>= 1;
        if (bit == 0u) {
            /* accumulate zero-run length */
            if (!in_zero) { in_zero = 1u; run_len = 1u; }
            else           { run_len++;               }
        } else {
            /* we just left a zero-run; check its parity */
            if (in_zero) {
                if (run_len & 1u) return 0u;   /* odd-length zero block */
                in_zero = 0u;
            }
        }
    }
    /* If the number ends (MSB side) in a zero-run, ignore it:
     * leading zeros are not part of the representation. */

    return 1u;
}

void test_baum_sweet(void)
{
    uint32_t count   = 0u;
    uint32_t xor_idx = 0u;
    uint32_t i;

    for (i = 0u; i < BS_N; i++) {
        if (baum_sweet(i)) {
            count++;
            xor_idx ^= i;
        }
    }

    /* count=13=0x0D, xor_idx=18=0x12
     * g_result = (32<<16)|(13<<8)|18 = 0x00200D12
     * Bytes: 0x20, 0x0D, 0x12 — distinct and non-zero */
    g_result = (BS_N << 16) | (count << 8) | (xor_idx & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_baum_sweet();
    for (;;);
}
