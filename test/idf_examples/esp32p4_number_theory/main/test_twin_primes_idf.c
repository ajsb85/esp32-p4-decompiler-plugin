/* test_twin_primes_idf.c
 *
 * IDF/FreeRTOS wrapper for bare-metal test_twin_primes.c fixture.
 *
 * Original fixture: test/roundtrip/test_twin_primes.c
 * Ported to IDF by removing the bare-metal _start() entry point,
 * adding Unity assertions, and printing RESULT:0x%08X for pytest-embedded.
 *
 * Algorithm: Find all twin-prime pairs (p, p+2) where both p and p+2 are
 * prime, p in [2..TP_UPPER-2].  Trial-division primality test.
 *
 * Known result for TP_UPPER=100:
 *   pair_count   = 8    (0x08)
 *   first_sum_mod = 236 (0xEC)  -- sum of first elements mod 256
 *   g_result = (TP_UPPER<<16) | (pair_count<<8) | first_sum_mod = 0x0064_08EC
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include "unity.h"

volatile uint32_t g_result;

#define TP_UPPER 100u

static uint32_t tp_is_prime(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if (n % 2u == 0u) return 0u;
    for (uint32_t d = 3u; d * d <= n; d += 2u) {
        if (n % d == 0u) return 0u;
    }
    return 1u;
}

void test_twin_primes_idf(void)
{
    uint32_t pair_count = 0u;
    uint32_t first_sum  = 0u;

    for (uint32_t p = 2u; p + 2u <= TP_UPPER; p++) {
        if (tp_is_prime(p) && tp_is_prime(p + 2u)) {
            pair_count++;
            first_sum += p;
        }
    }

    /* pair_count=8=0x08, first_sum_mod=236=0xEC, TP_UPPER=100=0x64 */
    g_result = (TP_UPPER << 16) | ((pair_count & 0xFFu) << 8) | (first_sum & 0xFFu);

    printf("RESULT:0x%08" PRIx32 "\n", (uint32_t)g_result);

    TEST_ASSERT_EQUAL_UINT32(8,   pair_count);
    TEST_ASSERT_EQUAL_UINT32(0xEC, first_sum & 0xFF);
    TEST_ASSERT_EQUAL_UINT32(0x006408ECu, (uint32_t)g_result);
}
