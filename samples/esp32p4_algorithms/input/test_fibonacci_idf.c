/* IDF-wrapped Fibonacci round-trip test for ESP32-P4. */
#include "algorithms.h"
#include <stdio.h>
#include <inttypes.h>
#include "unity.h"

void test_fibonacci_idf(void) {
    uint32_t a = 0, b = 1;
    uint32_t count = 0;
    /* Count Fibonacci numbers < 10000 */
    while (b < 10000) {
        uint32_t c = a + b;
        a = b; b = c;
        count++;
    }
    /* b is now the first Fib >= 10000 (10946); a is previous (6765) */
    uint32_t low8  = count & 0xFF;
    uint32_t mid8  = (a >> 5) & 0xFF;
    if (mid8 == 0) mid8 = 1;
    g_result = (count << 16) | (mid8 << 8) | low8;

    printf("FIBONACCI_RESULT:0x%08" PRIx32 "\n", (uint32_t)g_result);
    TEST_ASSERT_EQUAL(19, count);
}
