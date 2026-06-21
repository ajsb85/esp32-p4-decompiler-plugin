#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* Count primes below n using Sieve of Eratosthenes.
 * g_result encodes (n_tests, sum_counts, xor_counts). */

static int count_primes(int n) {
    if (n < 2) return 0;
    char *sieve = calloc((size_t)n, 1);
    for (int i = 0; i < n; i++) sieve[i] = 1;
    sieve[0] = sieve[1] = 0;
    for (int p = 2; p * p < n; p++)
        if (sieve[p])
            for (int j = p * p; j < n; j += p)
                sieve[j] = 0;
    int cnt = 0;
    for (int i = 2; i < n; i++) if (sieve[i]) cnt++;
    free(sieve);
    return cnt;
}

volatile uint32_t g_result;

void test_count_primes(void) {
    int r1 = count_primes(50);   /* 15 */
    int r2 = count_primes(100);  /* 25 */
    int r3 = count_primes(30);   /* 10 */
    int s  = r1 + r2 + r3;      /* 50 */
    int x  = r1 ^ r2 ^ r3;      /* 28 */
    g_result = (3u << 16) | ((uint32_t)s << 8) | (uint32_t)x; /* 0x0003321C */
}

__attribute__((noreturn)) void _start(void) {
    test_count_primes();
    for (;;);
}
