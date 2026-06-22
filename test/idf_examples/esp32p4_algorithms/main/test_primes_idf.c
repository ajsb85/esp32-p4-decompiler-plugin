/* IDF-wrapped prime sieve round-trip test for ESP32-P4. */
#include "algorithms.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "unity.h"

void test_primes_idf(void) {
    uint8_t sieve[100];
    memset(sieve, 1, sizeof(sieve));
    sieve[0] = sieve[1] = 0;
    for (int i = 2; i < 100; i++) {
        if (!sieve[i]) continue;
        for (int j = i*i; j < 100; j += i) sieve[j] = 0;
    }
    uint32_t count = 0, sum = 0;
    for (int i = 2; i < 100; i++) {
        if (sieve[i]) { count++; sum += i; }
    }
    uint32_t low8  = count & 0xFF;
    uint32_t mid8  = (sum / count) & 0xFF;
    if (mid8 == 0) mid8 = 1;
    g_result = (count << 16) | (mid8 << 8) | low8;

    printf("PRIMES_RESULT:0x%08" PRIx32 "\n", (uint32_t)g_result);
    TEST_ASSERT_EQUAL(25, count);   /* 25 primes below 100 */
}
