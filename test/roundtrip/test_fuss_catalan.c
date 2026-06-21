/* test_fuss_catalan.c
 * Fuss-Catalan numbers: A_m(p, r) = r/(mp+r) * C(mp+r, m)
 * The m-th Fuss-Catalan number for parameter p is: C_p(m) = C((p+1)*m, m) / (p*m+1)
 * For p=2: ordinary Catalan C(m) = C(2m,m)/(m+1)
 * For p=3: ternary trees: C3(m) = C(3m,m)/(2m+1)
 * We compute Fuss-Catalan numbers for small m and two values of p using integer formulas.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_fuss_catalan.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Compute C(n, k) using the multiplicative formula for small n.
 * Returns exact value (assumes no overflow for n <= 20).
 */
static uint32_t comb(uint32_t n, uint32_t k) {
    if (k > n) return 0;
    if (k == 0 || k == n) return 1;
    if (k > n - k) k = n - k;
    uint32_t result = 1;
    uint32_t i;
    for (i = 0; i < k; i++) {
        result = result * (n - i) / (i + 1);
    }
    return result;
}

/* Fuss-Catalan number for order p at index m:
 *   FC(p, m) = C((p+1)*m, m) / (p*m + 1)
 * For p=1: C(2m,m)/(m+1) — ordinary Catalan numbers
 * For p=2: C(3m,m)/(2m+1) — ternary tree enumerations
 * For p=3: C(4m,m)/(3m+1)
 */
static uint32_t fuss_catalan(uint32_t p, uint32_t m) {
    if (m == 0) return 1;
    uint32_t n = (p + 1) * m;
    uint32_t denom = p * m + 1;
    /* C((p+1)*m, m) is always divisible by (p*m+1) */
    return comb(n, m) / denom;
}

void _start(void) {
    /* Compute FC(p, m) for p in {1,2,3} and m in {0..4} */
    /* p=1: Catalan: 1,1,2,5,14 */
    /* p=2: ternary: 1,1,3,12,55 */
    /* p=3: quaternary: 1,1,4,22,140 */
    uint32_t sum = 0;
    uint32_t xor_acc = 0;
    uint32_t p, m;
    for (p = 1; p <= 3; p++) {
        for (m = 0; m <= 4; m++) {
            uint32_t fc = fuss_catalan(p, m);
            sum += fc;
            xor_acc ^= fc;
        }
    }

    uint32_t n_tests  = 15;  /* 3 p-values * 5 m-values */
    uint32_t metric_a = sum & 0xFF;       /* sum of all FC numbers mod 256 */
    uint32_t metric_b = xor_acc & 0xFF;  /* XOR of all FC numbers mod 256 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;

    while (1) {}
}
