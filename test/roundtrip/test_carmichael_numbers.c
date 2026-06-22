/*
 * test_carmichael_numbers.c
 * Carmichael numbers: composite n where b^(n-1) ≡ 1 (mod n) for all gcd(b,n)=1.
 * Self-contained, 32-bit only (n <= 10000, so b < 10000 → b*b < 2^27, safe).
 * No stdlib.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Modular exponentiation: base^exp mod m, 32-bit safe for m <= 10000 */
static uint32_t powmod32(uint32_t base, uint32_t exp, uint32_t m) {
    uint32_t result = 1u;
    base %= m;
    while (exp > 0u) {
        if (exp & 1u) {
            result = (result * base) % m;
        }
        base = (base * base) % m;
        exp >>= 1u;
    }
    return result;
}

/* Trial division primality test */
static uint32_t is_prime(uint32_t n) {
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t i = 3u; i * i <= n; i += 2u) {
        if (n % i == 0u) return 0u;
    }
    return 1u;
}

static uint32_t gcd32(uint32_t a, uint32_t b) {
    while (b) { uint32_t t = b; b = a % b; a = t; }
    return a;
}

/*
 * Carmichael test: composite n where b^(n-1) ≡ 1 (mod n) for all coprime b.
 * We test bases 2..limit.
 */
static uint32_t is_carmichael(uint32_t n) {
    if (n < 561u) return 0u;
    if (is_prime(n)) return 0u;
    uint32_t nm1 = n - 1u;
    /* Test bases 2..50 (sufficient for n <= 10000) */
    for (uint32_t b = 2u; b <= 50u; b++) {
        if (gcd32(b, n) != 1u) continue;
        if (powmod32(b, nm1, n) != 1u) return 0u;
    }
    return 1u;
}

void _start(void) {
    /*
     * Count Carmichael numbers in [1, 10000].
     * Known: 561, 1105, 1729, 2465, 2821, 6601, 8911 → count = 7.
     */
    uint32_t count = 0u;
    uint32_t csum  = 0u;

    for (uint32_t n = 561u; n <= 10000u; n += 2u) {
        if (is_carmichael(n)) {
            count++;
            csum += (n >> 5u);
        }
    }

    uint32_t n_tests  = 100u;             /* 0x64 */
    uint32_t metric_a = count & 0xFFu;    /* 0x07 */
    uint32_t metric_b = csum  & 0xFFu;    /* distinct, non-zero */

    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
