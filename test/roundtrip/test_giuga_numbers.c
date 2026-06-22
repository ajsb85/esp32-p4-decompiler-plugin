/* test_giuga_numbers.c
 * Giuga numbers: composite numbers n such that for each prime factor p of n,
 * p divides (n/p - 1).  Equivalently, n is Giuga iff n is composite and
 * p^2 divides (n - p) for each prime p | n.
 *
 * These are extremely rare.  Known values: 30, 858, 1722, 66198, ...
 *
 * In [1..99]: only 30 is a Giuga number.
 *   count = 1, sum = 30
 *   metric_a = 1  & 0xFF = 0x01
 *   metric_b = 30 % 251  = 30 = 0x1E
 *   n_tests  = 99         = 0x63
 *   g_result = (99<<16)|(1<<8)|30 = 0x0063011E
 *   Bytes: 0x63=99, 0x01=1, 0x1E=30 — non-zero and distinct.
 *
 * Verification of n=30: prime factors 2, 3, 5.
 *   p=2: (30/2 - 1) = 14; 2 | 14 ✓
 *   p=3: (30/3 - 1) = 9;  3 | 9  ✓
 *   p=5: (30/5 - 1) = 5;  5 | 5  ✓
 *   30 is composite ✓  =>  30 is a Giuga number.
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_giuga_numbers.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Check if n is a Giuga number.
 * Returns 1 if composite AND for each prime p | n: p | (n/p - 1). */
static uint32_t is_giuga(uint32_t n)
{
    if (n < 2u) return 0u;

    uint32_t temp  = n;
    uint32_t nprimes = 0u;  /* count distinct prime factors */

    for (uint32_t d = 2u; d * d <= temp; d++) {
        if (temp % d == 0u) {
            nprimes++;
            /* Check Giuga condition: d | (n/d - 1) */
            if ((n / d) < 1u) return 0u;
            if ((n / d - 1u) % d != 0u) return 0u;
            /* Remove all occurrences of d */
            while (temp % d == 0u) temp /= d;
        }
    }
    if (temp > 1u) {
        /* temp is a prime factor */
        nprimes++;
        if ((n / temp) < 1u) return 0u;
        if ((n / temp - 1u) % temp != 0u) return 0u;
    }

    /* Must be composite (at least 2 distinct prime factors, or repeated factor) */
    /* Primality: if nprimes == 1 and temp_orig == d^k for one prime, it's prime power.
     * Simplest check: composite means n has more than one factor, i.e., n != its only prime. */
    /* If nprimes == 1 and temp == 1 (fully divided), then n is a prime power.
     * A prime is not composite; prime powers p^k with k>1 could be composite.
     * But Giuga condition p|(n/p-1) for p^2: n/p=p^(k-1), need p|(p^(k-1)-1).
     * p|(p^(k-1)-1) => p|(-1) => impossible. So prime powers never qualify.
     * Thus composite Giuga numbers must have >= 2 distinct prime factors. */
    if (nprimes < 2u) return 0u;

    return 1u;
}

void _start(void)
{
    uint32_t n_tests = 99u;
    uint32_t count   = 0u;
    uint32_t gsum    = 0u;

    for (uint32_t n = 1u; n <= n_tests; n++) {
        if (is_giuga(n)) {
            count++;
            gsum += n;
        }
    }

    /* In [1..99]: count=1 (only 30), sum=30
     * metric_a = 1 & 0xFF   = 0x01
     * metric_b = 30 % 251   = 30 = 0x1E
     * g_result = (99<<16)|(1<<8)|30 = 0x0063011E */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = gsum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
