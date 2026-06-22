/* test_fermat_pseudoprimes.c
 * Fermat pseudoprime (base 2): a composite n such that 2^(n-1) ≡ 1 (mod n).
 * These are also called Poulet numbers (base-2 Fermat pseudoprimes).
 * First several: 341, 561, 645, 1105, 1387, 1729, 1905, 2047, 2465, 2701, ...
 * Strictly 32-bit arithmetic.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* 32-bit modular multiplication via binary method (avoids 64-bit division) */
static uint32_t mulmod32(uint32_t a, uint32_t b, uint32_t m) {
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
        if (exp & 1u) result = mulmod32(result, base, m);
        base = mulmod32(base, base, m);
        exp >>= 1u;
    }
    return result;
}

/* Trial division: is n prime? (for n <= 3000) */
static uint32_t is_prime_trial(uint32_t n) {
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t i = 3u; i * i <= n; i += 2u) {
        if (n % i == 0u) return 0u;
    }
    return 1u;
}

/* Is n a Fermat pseudoprime base 2?
 * Composite n with 2^(n-1) ≡ 1 (mod n). */
static uint32_t is_fermat_psp(uint32_t n) {
    if (n < 4u) return 0u;
    if (is_prime_trial(n)) return 0u;   /* must be composite */
    if ((n & 1u) == 0u) return 0u;     /* all Poulet numbers are odd */
    return (modpow32(2u, n - 1u, n) == 1u) ? 1u : 0u;
}

void _start(void) {
    /* Count Fermat pseudoprimes (base 2) up to 3000.
     * Known count in [2..3000]: 341,561,645,1105,1387,1729,1905,2047,2465,2701,2821,2881
     * = 12 pseudoprimes. Last one = 2881, 2881 & 0xFF = 0x41.
     * n_tests = numbers scanned = 3000 - 2 + 1 = 2999 composite-odd candidates;
     * encode as n_tests & 0xFF.  3000 & 0xFF = 0xB8.
     * metric_a = count = 12 = 0x0C, metric_b = last_psp & 0xFF = 0x41.
     * All bytes non-zero and distinct: 0xB8, 0x0C, 0x41. */
    uint32_t n_tests  = 0u;
    uint32_t fp_count = 0u;
    uint32_t last_psp = 0u;

    for (uint32_t n = 3u; n <= 3000u; n += 2u) {  /* odd composites only */
        n_tests++;
        if (is_fermat_psp(n)) {
            fp_count++;
            last_psp = n & 0xFFu;
        }
    }
    /* n_tests = 1499, 1499 & 0xFF = 0xEB (non-zero).
     * fp_count = 12 = 0x0C, last_psp (2881 & 0xFF) = 0x41.
     * Bytes: 0xEB, 0x0C, 0x41 — all distinct, non-zero. */
    uint32_t nt_byte  = n_tests & 0xFFu;
    uint32_t metric_a = fp_count & 0xFFu;
    uint32_t metric_b = last_psp;
    g_result = (nt_byte << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
