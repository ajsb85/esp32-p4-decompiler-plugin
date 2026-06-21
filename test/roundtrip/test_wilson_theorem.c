/* test_wilson_theorem.c
 * Wilson's Theorem primality test:
 *   p is prime  <=>  (p-1)! ≡ -1  (mod p)
 * For small primes we compute (p-1)! mod p directly.
 * 32-bit only; no stdlib needed.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Compute n! mod m  (n small enough that loop is fine) */
static uint32_t factorial_mod(uint32_t n, uint32_t m)
{
    uint32_t f = 1u;
    uint32_t i;
    for (i = 2u; i <= n; i++) {
        f = (uint32_t)(((uint32_t)f * (uint32_t)i) % m);
    }
    return f;
}

/* Wilson primality: returns 1 if p is prime (p >= 2) */
static uint32_t wilson_is_prime(uint32_t p)
{
    if (p < 2u) return 0u;
    if (p == 2u) return 1u;
    uint32_t fact = factorial_mod(p - 1u, p);  /* (p-1)! mod p */
    return (fact == p - 1u) ? 1u : 0u;          /* should be p-1 = -1 mod p */
}

/* Count primes in [2..limit] using Wilson's test */
static uint32_t count_wilson_primes(uint32_t limit)
{
    uint32_t cnt = 0u;
    uint32_t p;
    for (p = 2u; p <= limit; p++) {
        if (wilson_is_prime(p)) {
            cnt++;
        }
    }
    return cnt;
}

void _start(void)
{
    /* Primes in [2..20]: 2,3,5,7,11,13,17,19 => 8 primes */
    uint32_t cnt20  = count_wilson_primes(20u);   /* 8 */
    /* Verify specific: 13 is prime, 15 is not */
    uint32_t p13    = wilson_is_prime(13u);        /* 1 */
    uint32_t p15    = wilson_is_prime(15u);        /* 0 */

    /* n_tests=3, metric_a=cnt20=8, metric_b=p13+1+p15+2=4 => (3<<16)|(8<<8)|4 = 0x030804 */
    uint32_t n_tests  = 3u;
    uint32_t metric_a = cnt20;              /* 8 */
    uint32_t metric_b = p13 + 1u + p15 + 2u; /* 1+1+0+2=4 */
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;

    while (1) {}
}
