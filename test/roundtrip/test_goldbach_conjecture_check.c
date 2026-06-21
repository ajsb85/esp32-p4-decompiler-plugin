/*
 * test_goldbach_conjecture_check.c
 * Goldbach Conjecture verification: every even integer > 2 can be expressed
 * as the sum of two prime numbers.
 *
 * Algorithm:
 *   1. Build a prime sieve (simple Eratosthenes) up to the test limit.
 *   2. For each even n in range, find prime p <= n/2 such that (n-p) is also prime.
 *   3. Count pairs found and verify all even numbers in range are Goldbach-representable.
 *
 * Additional checks:
 *   - For n=28: find smallest Goldbach prime p (p=5, 28-5=23 prime).
 *   - Verify n=100: find a valid pair (e.g. p=3, 97 is prime).
 *   - Count distinct Goldbach pairs for n=30: (7,23),(11,19),(13,17) => 3 pairs.
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define GOLD_LIMIT 101u

static uint8_t gold_is_prime[GOLD_LIMIT];

static void build_sieve(void) {
    for (uint32_t i = 0u; i < GOLD_LIMIT; i++) gold_is_prime[i] = 1u;
    gold_is_prime[0u] = 0u;
    gold_is_prime[1u] = 0u;
    for (uint32_t i = 2u; i * i < GOLD_LIMIT; i++) {
        if (gold_is_prime[i]) {
            for (uint32_t j = i * i; j < GOLD_LIMIT; j += i) {
                gold_is_prime[j] = 0u;
            }
        }
    }
}

/* Find the smallest prime p such that p + (n-p) = n and n-p is also prime.
 * Returns p, or 0 if none found (conjecture holds => always found for even n>2).
 */
static uint32_t goldbach_smallest(uint32_t n) {
    for (uint32_t p = 2u; p <= n / 2u; p++) {
        if (gold_is_prime[p] && gold_is_prime[n - p]) {
            return p;
        }
    }
    return 0u;
}

/* Count distinct unordered prime pairs {p, q} with p<=q, p+q=n */
static uint32_t goldbach_count_pairs(uint32_t n) {
    uint32_t cnt = 0u;
    for (uint32_t p = 2u; p <= n / 2u; p++) {
        if (gold_is_prime[p] && gold_is_prime[n - p]) {
            cnt++;
        }
    }
    return cnt;
}

/* Verify all even numbers in [4, limit-1] satisfy Goldbach */
static uint32_t goldbach_verify_all(uint32_t limit) {
    for (uint32_t n = 4u; n < limit; n += 2u) {
        if (goldbach_smallest(n) == 0u) return 0u;
    }
    return 1u;
}

static uint32_t run_goldbach_tests(void) {
    uint32_t n_tests = 0u;

    build_sieve();

    /*
     * Test 1: Smallest Goldbach prime for n=28.
     * 28 = 5 + 23 (both prime, 5 is smallest such p).
     */
    uint32_t p28 = goldbach_smallest(28u);
    n_tests++;
    /* p28 == 5 */

    /*
     * Test 2: Count distinct Goldbach pairs for n=30.
     * 30 = 7+23 = 11+19 = 13+17 => 3 pairs.
     */
    uint32_t pairs30 = goldbach_count_pairs(30u);
    n_tests++;
    /* pairs30 == 3 */

    /*
     * Test 3: Verify all even numbers in [4,100] satisfy Goldbach.
     * Expected: 1 (all verified OK).
     */
    uint32_t all_ok = goldbach_verify_all(101u);
    n_tests++;
    /* all_ok == 1 */

    /*
     * Pack result:
     * n_tests = 3 = 0x03
     * metric_a = (p28 << 4) | pairs30
     *          = (5 << 4) | 3 = 80 | 3 = 83 = 0x53
     * metric_b = (all_ok << 7) | (pairs30 << 4) | p28
     *          = (1<<7)|(3<<4)|5 = 128|48|5 = 181 = 0xB5
     * Result = (0x03<<16)|(0x53<<8)|0xB5 = 0x0353B5
     * Bytes: 0x03, 0x53, 0xB5 — non-zero, distinct. Good.
     */
    uint32_t metric_a = (p28 << 4u) | pairs30;
    uint32_t metric_b = (all_ok << 7u) | (pairs30 << 4u) | p28;
    return (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    g_result = run_goldbach_tests();
    while (1) {}
}
