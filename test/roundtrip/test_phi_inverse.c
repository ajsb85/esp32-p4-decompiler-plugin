/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Phi Inverse (Inverse Totient) fixture.
 *
 * For a given value m, find all n <= LIMIT such that phi(n) == m, where phi
 * is Euler's totient function.  The inverse totient is computed by:
 *   1. Sieve phi values for all n up to LIMIT (phi sieve with prime factoring)
 *   2. Collect all n where phi_sieve[n] == target_m
 *
 * Distinctive decompiler idioms:
 *   1. Phi sieve init: `phi_sieve[i] = i` followed by prime scan
 *   2. Prime reduction: `phi_sieve[j] -= phi_sieve[j] / i` for each prime i
 *   3. Inner divisibility: `for(j=i; j<=LIMIT; j+=i) if(phi_sieve[j]==j)...`
 *   4. Inverse collection: accumulate n where `phi_sieve[n] == target_m`
 *   5. Result XOR fold: xor all matching n values into a checksum
 *
 * Test: target_m = 4 (phi(n)=4 for n in {5,8,10,12})
 *   inv_count = 4
 *   xor_vals  = 5^8^10^12 = 11 = 0x0B
 *   checksum  = (4 + 11) & 0xFF = 15 = 0x0F
 *   g_result  = (4<<16)|(11<<8)|15 = 0x040B0F
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PHI_LIMIT  16
#define TARGET_M   4

static uint32_t phi_sieve[PHI_LIMIT + 1];

static void phi_inv_sieve(void)
{
    for (uint32_t i = 0; i <= PHI_LIMIT; i++)
        phi_sieve[i] = i;

    for (uint32_t i = 2; i <= PHI_LIMIT; i++) {
        if (phi_sieve[i] == i) {          /* i is prime */
            for (uint32_t j = i; j <= PHI_LIMIT; j += i)
                phi_sieve[j] -= phi_sieve[j] / i;
        }
    }
}

void test_phi_inverse(void)
{
    phi_inv_sieve();

    uint32_t inv_count = 0u;
    uint32_t xor_vals  = 0u;

    for (uint32_t n = 1; n <= PHI_LIMIT; n++) {
        if (phi_sieve[n] == TARGET_M) {
            inv_count++;
            xor_vals ^= n;
        }
    }

    uint32_t checksum = (inv_count + xor_vals) & 0xFFu;
    g_result = (inv_count << 16) | (xor_vals << 8) | checksum;
}

__attribute__((noreturn)) void _start(void)
{
    test_phi_inverse();
    for (;;);
}
