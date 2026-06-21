/*
 * test_sieve_of_atkin.c
 * Sieve of Atkin: an optimised prime-finding algorithm that uses a modified
 * sieve based on quadratic forms rather than division.
 *
 * Algorithm overview (limited to 32-bit arithmetic, no 64-bit ops):
 *   1. For every (x,y) with 1 <= x,y <= sqrt(limit):
 *      - n = 4x^2 + y^2: flip n's prime flag if n % 12 == 1 or 5
 *      - n = 3x^2 + y^2: flip n's prime flag if n % 12 == 7
 *      - n = 3x^2 - y^2 (x>y): flip n's prime flag if n % 12 == 11
 *   2. Eliminate square multiples of each prime >= 5.
 *   3. 2 and 3 are primes by convention.
 *
 * Tests:
 *   1. Count of primes up to 100 (known: 25).
 *   2. Count of primes up to 50  (known: 15).
 *   3. Check that 97 is prime and 91 is not prime.
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define ATKIN_LIMIT 101u

/* is_prime flag array; index = number */
static uint8_t atkin_flags[ATKIN_LIMIT];

/* Integer square root (floor) — pure 32-bit */
static uint32_t isqrt32(uint32_t n) {
    if (n == 0u) return 0u;
    uint32_t x = n;
    uint32_t y = (x + 1u) >> 1u;
    while (y < x) {
        x = y;
        y = (x + n / x) >> 1u;
    }
    return x;
}

static void atkin_sieve(uint32_t limit) {
    /* Clear flags */
    for (uint32_t i = 0u; i < limit; i++) atkin_flags[i] = 0u;

    if (limit > 2u) atkin_flags[2u] = 1u;
    if (limit > 3u) atkin_flags[3u] = 1u;

    uint32_t sqrtlim = isqrt32(limit);

    for (uint32_t x = 1u; x <= sqrtlim; x++) {
        uint32_t x2 = x * x;
        for (uint32_t y = 1u; y <= sqrtlim; y++) {
            uint32_t y2 = y * y;

            /* Form 4x^2 + y^2 */
            uint32_t n = 4u * x2 + y2;
            if (n < limit) {
                uint32_t r = n % 12u;
                if (r == 1u || r == 5u) atkin_flags[n] ^= 1u;
            }

            /* Form 3x^2 + y^2 */
            n = 3u * x2 + y2;
            if (n < limit && (n % 12u) == 7u) atkin_flags[n] ^= 1u;

            /* Form 3x^2 - y^2 (only when x > y) */
            if (x > y) {
                n = 3u * x2 - y2;
                if (n < limit && (n % 12u) == 11u) atkin_flags[n] ^= 1u;
            }
        }
    }

    /* Eliminate composites: for each prime r >= 5, clear all r^2 multiples */
    for (uint32_t r = 5u; r * r < limit; r++) {
        if (atkin_flags[r]) {
            uint32_t r2 = r * r;
            for (uint32_t k = r2; k < limit; k += r2) {
                atkin_flags[k] = 0u;
            }
        }
    }
}

static uint32_t atkin_count_primes(uint32_t limit) {
    uint32_t count = 0u;
    for (uint32_t i = 2u; i < limit; i++) {
        if (atkin_flags[i]) count++;
    }
    return count;
}

static uint32_t run_atkin_tests(void) {
    uint32_t n_tests = 0u;

    /*
     * Test 1: Count primes up to 100.
     * Expected: 25 primes (2,3,5,7,...,97).
     */
    atkin_sieve(ATKIN_LIMIT);
    uint32_t cnt100 = atkin_count_primes(101u);
    n_tests++;
    /* cnt100 == 25 */

    /*
     * Test 2: Count primes up to 50.
     * Expected: 15 primes (2,3,5,7,11,13,17,19,23,29,31,37,41,43,47).
     */
    uint32_t cnt50 = atkin_count_primes(51u);
    n_tests++;
    /* cnt50 == 15 */

    /*
     * Test 3: 97 is prime, 91 is not (91 = 7 * 13).
     */
    uint32_t is_97_prime = atkin_flags[97u];
    uint32_t is_91_prime = atkin_flags[91u];
    n_tests++;
    /* is_97_prime == 1, is_91_prime == 0 */

    /*
     * Pack result:
     * n_tests = 3 = 0x03
     * metric_a = cnt100 = 25 = 0x19
     * metric_b = (cnt50 << 4) | (is_97_prime << 3) | (is_91_prime << 2) | 1
     *          = (15 << 4) | (1 << 3) | (0 << 2) | 1
     *          = 240 | 8 | 0 | 1 = 249 = 0xF9
     * Result = (0x03<<16)|(0x19<<8)|0xF9 = 0x0319F9
     * Bytes: 0x03, 0x19, 0xF9 — non-zero, distinct. Good.
     */
    uint32_t metric_a = cnt100;
    uint32_t metric_b = (cnt50 << 4u) | (is_97_prime << 3u) | (is_91_prime << 2u) | 1u;
    return (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    g_result = run_atkin_tests();
    while (1) {}
}
