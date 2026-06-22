/* test_wieferich_primes.c
 * Wieferich prime check: a prime p is Wieferich if 2^(p-1) ≡ 1 (mod p^2).
 * Only two known Wieferich primes <= 3511: 1093 and 3511.
 * All arithmetic is strictly 32-bit (p^2 <= 3511^2 = 12327121 < 2^24,
 * so intermediate products fit in 32-bit with careful reduction).
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Multiply a*b mod m where a,b < m < 2^14 (so a*b < 2^28, fits in uint32_t) */
static uint32_t mulmod32(uint32_t a, uint32_t b, uint32_t m) {
    /* m = p^2 <= 3511^2 = 12327121 < 2^24.
     * a,b < m < 2^24, so a*b < 2^48 — needs manual 32-bit reduction.
     * Use binary method: accumulate with doubling, reducing mod m each step. */
    uint32_t result = 0u;
    a = a % m;
    while (b > 0u) {
        if (b & 1u) {
            result += a;
            if (result >= m) result -= m;
        }
        a += a;
        if (a >= m) a -= m;
        b >>= 1u;
    }
    return result;
}

/* Compute base^exp mod m */
static uint32_t modpow32(uint32_t base, uint32_t exp, uint32_t m) {
    uint32_t result = 1u % m;
    base = base % m;
    while (exp > 0u) {
        if (exp & 1u) {
            result = mulmod32(result, base, m);
        }
        base = mulmod32(base, base, m);
        exp >>= 1u;
    }
    return result;
}

/* Trial-division primality for n <= 3600 */
static uint32_t is_prime(uint32_t n) {
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t i = 3u; i * i <= n; i += 2u) {
        if (n % i == 0u) return 0u;
    }
    return 1u;
}

/* Check if prime p is a Wieferich prime: 2^(p-1) ≡ 1 (mod p^2) */
static uint32_t is_wieferich(uint32_t p) {
    uint32_t p2 = p * p;
    uint32_t val = modpow32(2u, p - 1u, p2);
    return (val == 1u) ? 1u : 0u;
}

void _start(void) {
    /* Scan primes up to 3600 and count Wieferich primes.
     * Known: 1093 and 3511.
     * n_tests counts primes checked (capped), w_count = 2, last_wp = 3511 & 0xFF = 0xB7
     * Encode: (nt_byte<<16)|(metric_a<<8)|metric_b
     * nt_byte = n_tests & 0xFF (non-zero), metric_a = w_count = 0x02, metric_b = 0xB7 */
    uint32_t n_tests  = 0u;
    uint32_t w_count  = 0u;
    uint32_t last_wp  = 0u;

    for (uint32_t n = 2u; n <= 3600u; n++) {
        if (is_prime(n)) {
            n_tests++;
            if (is_wieferich(n)) {
                w_count++;
                last_wp = n & 0xFFu;
            }
        }
    }
    /* n_tests = 508 primes up to 3600; 508 & 0xFF = 0xFC (non-zero)
     * w_count = 2 = 0x02, last_wp = 3511 & 0xFF = 0xB7
     * All three bytes non-zero and distinct. */
    uint32_t nt_byte  = n_tests & 0xFFu;
    uint32_t metric_a = w_count & 0xFFu;
    uint32_t metric_b = last_wp;
    g_result = (nt_byte << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
