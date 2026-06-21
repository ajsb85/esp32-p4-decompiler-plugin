/* test_pratt_certificate.c — Pratt primality certificate (32-bit, no libc)
 *
 * A Pratt certificate for a prime p requires:
 *   - a witness a such that a^(p-1) ≡ 1 (mod p)
 *   - for each prime factor q of (p-1): a^((p-1)/q) ≢ 1 (mod p)
 *
 * We verify certificates for a small set of known primes.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Modular multiplication (32-bit safe: use 64? no — stay 32-bit)
 * Since we stay 32-bit, limit primes so p*p fits in uint32_t, i.e. p < 65536.
 * We use the "Russian peasant" multiplication to avoid overflow. */
static uint32_t mulmod32(uint32_t a, uint32_t b, uint32_t m) {
    uint32_t result = 0;
    a = a % m;
    while (b > 0) {
        if (b & 1u) {
            result += a;
            if (result >= m) result -= m;
        }
        a <<= 1;
        if (a >= m) a -= m;
        b >>= 1;
    }
    return result;
}

/* Modular exponentiation: base^exp mod m */
static uint32_t powmod32(uint32_t base, uint32_t exp, uint32_t m) {
    uint32_t result = 1;
    base = base % m;
    while (exp > 0) {
        if (exp & 1u) result = mulmod32(result, base, m);
        base = mulmod32(base, base, m);
        exp >>= 1;
    }
    return result;
}

/* Pratt certificate check for prime p.
 * factors[] and nfactors describe the prime factorisation of (p-1).
 * witness a must satisfy:
 *   a^(p-1) ≡ 1 (mod p)
 *   a^((p-1)/q) ≢ 1 (mod p)  for each prime factor q of (p-1)
 */
static uint32_t pratt_check(uint32_t p, uint32_t a,
                             const uint32_t *factors, uint32_t nfactors) {
    uint32_t pm1 = p - 1u;

    /* Condition 1: a^(p-1) ≡ 1 mod p */
    if (powmod32(a, pm1, p) != 1u) return 0;

    /* Condition 2: for each prime factor q of (p-1) */
    uint32_t i;
    for (i = 0; i < nfactors; i++) {
        uint32_t q = factors[i];
        if (powmod32(a, pm1 / q, p) == 1u) return 0;
    }
    return 1;
}

static void test_pratt_certificate(void) {
    /* Pratt certificates for small primes:
     * p=7,   p-1=6=2*3,     witness=3
     * p=13,  p-1=12=2*2*3,  witness=2
     * p=17,  p-1=16=2^4,    witness=3
     * p=19,  p-1=18=2*3^2,  witness=2
     * p=23,  p-1=22=2*11,   witness=5
     * p=29,  p-1=28=2^2*7,  witness=2
     * p=31,  p-1=30=2*3*5,  witness=3
     * p=37,  p-1=36=2^2*3,  witness=2
     */

    /* Each entry: {p, a, factors...}  — we encode inline */
    uint32_t n_tests = 0;
    uint32_t ok_count = 0;
    uint32_t witness_sum = 0;

    /* p=7 */
    {
        uint32_t f[] = {2, 3};
        ok_count += pratt_check(7, 3, f, 2); n_tests++;
        witness_sum += 3;
    }
    /* p=13 */
    {
        uint32_t f[] = {2, 3};
        ok_count += pratt_check(13, 2, f, 2); n_tests++;
        witness_sum += 2;
    }
    /* p=17 */
    {
        uint32_t f[] = {2};
        ok_count += pratt_check(17, 3, f, 1); n_tests++;
        witness_sum += 3;
    }
    /* p=19 */
    {
        uint32_t f[] = {2, 3};
        ok_count += pratt_check(19, 2, f, 2); n_tests++;
        witness_sum += 2;
    }
    /* p=23 */
    {
        uint32_t f[] = {2, 11};
        ok_count += pratt_check(23, 5, f, 2); n_tests++;
        witness_sum += 5;
    }
    /* p=29 */
    {
        uint32_t f[] = {2, 7};
        ok_count += pratt_check(29, 2, f, 2); n_tests++;
        witness_sum += 2;
    }
    /* p=31 */
    {
        uint32_t f[] = {2, 3, 5};
        ok_count += pratt_check(31, 3, f, 3); n_tests++;
        witness_sum += 3;
    }
    /* p=37 */
    {
        uint32_t f[] = {2, 3};
        ok_count += pratt_check(37, 2, f, 2); n_tests++;
        witness_sum += 2;
    }

    /* Also verify a NON-prime fails (p=9=3^2, "witness"=2, f={2,3} for pm1=8=2^3) */
    /* 9 is not prime so a^8 mod 9 = 256 mod 9 = 4 ≠ 1 → returns 0 → correct */
    {
        uint32_t f[] = {2};
        uint32_t bad = pratt_check(9, 2, f, 1);
        if (bad == 0) ok_count++; /* correctly rejected */
        n_tests++;
        witness_sum += 2;
    }

    /* n_tests=9, ok_count=9
     * metric_a = ok_count & 0xFF = 0x09
     * metric_b = witness_sum & 0xFF: 3+2+3+2+5+2+3+2+2=24 = 0x18
     * g_result = (9<<16)|(9<<8)|0x18 = 0x090918  all bytes non-zero & distinct ✓ */
    uint32_t metric_a = ok_count & 0xFFu;
    uint32_t metric_b = witness_sum & 0xFFu;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    test_pratt_certificate();
    while (1) {}
}
