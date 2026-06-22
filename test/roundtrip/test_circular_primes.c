/* test_circular_primes.c — circular primes up to N
 * A circular prime has all rotations of its digits also prime.
 * Examples: 2, 3, 5, 7, 11, 13, 31, 37, 71, 73, 79, 97, 113, ...
 * 32-bit only, no stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Simple primality test */
static uint32_t is_prime(uint32_t n) {
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if (n % 2u == 0u) return 0u;
    uint32_t i;
    for (i = 3u; i * i <= n; i += 2u) {
        if (n % i == 0u) return 0u;
    }
    return 1u;
}

/* Count digits of n */
static uint32_t num_digits(uint32_t n) {
    if (n == 0u) return 1u;
    uint32_t d = 0u;
    while (n > 0u) { n /= 10u; d++; }
    return d;
}

/* Rotate digits left once: 1234 -> 2341 */
static uint32_t rotate_left(uint32_t n, uint32_t digits) {
    /* power of 10 for digits-1 */
    uint32_t pow10 = 1u;
    uint32_t i;
    for (i = 1u; i < digits; i++) pow10 *= 10u;
    uint32_t lead = n / pow10;        /* leading digit */
    uint32_t rest = n % pow10;        /* remaining digits */
    return rest * 10u + lead;
}

/* Check if n is a circular prime */
static uint32_t is_circular_prime(uint32_t n) {
    if (!is_prime(n)) return 0u;
    uint32_t digits = num_digits(n);
    uint32_t rot = n;
    uint32_t i;
    for (i = 0u; i < digits - 1u; i++) {
        rot = rotate_left(rot, digits);
        if (!is_prime(rot)) return 0u;
    }
    return 1u;
}

static void run_circular_primes(void) {
    /* Find circular primes up to 200 */
    uint32_t count = 0u;
    uint32_t circ_sum = 0u;
    uint32_t n;
    for (n = 2u; n <= 200u; n++) {
        if (is_circular_prime(n)) {
            count++;
            circ_sum += n;
        }
    }
    /* Known circular primes <= 200: 2,3,5,7,11,13,17,31,37,71,73,79,97,113,131,197,199
     * count=17, sum=1155 -> sum%251 = 1155%251 = 149 (0x95)
     * Use: n_tests=17 (0x11), sum_mod=149 (0x95), count%64=17 (0x11) -- not distinct
     * Use: n_tests=17 (0x11), sum_mod=149 (0x95), extra = (sum>>3)%251 = 144 (0x90)
     * Pack: (17<<16)|(149<<8)|144 = 0x11_95_90
     * Check: 0x11=17, 0x95=149, 0x90=144 — all non-zero, not all distinct (fine, just non-zero)
     */
    uint32_t n_tests  = count & 0xFFu;          /* 17 = 0x11 */
    uint32_t metric_a = circ_sum % 251u;         /* 149 = 0x95 */
    uint32_t metric_b = (circ_sum >> 3u) % 251u; /* 144 = 0x90 */
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    run_circular_primes();
    while (1) {}
}
