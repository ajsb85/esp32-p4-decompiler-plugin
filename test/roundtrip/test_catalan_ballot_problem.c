/* test_catalan_ballot_problem.c
 * Ballot problem / Catalan numbers via the ballot problem formula.
 * P(A always strictly ahead) = (a-b)/(a+b) for a votes for A, b for B (a>b).
 * Equivalent: count paths from (0,0) to (a+b, a-b) staying strictly above x-axis
 * = C(a+b, a) - C(a+b, a+1)  = Catalan-related ballot counts.
 * We compute ballot numbers B(a,b) = C(a+b,a)*(a-b)/(a+b) using integer arithmetic.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_catalan_ballot_problem.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Compute C(n, k) mod a prime for small n using Pascal's triangle row.
 * We use a simple iterative formula: C(n,k) = C(n,k-1)*(n-k+1)/k
 * This works exactly for small n where intermediate products fit in 32 bits.
 */
static uint32_t comb(uint32_t n, uint32_t k) {
    if (k > n) return 0;
    if (k == 0 || k == n) return 1;
    if (k > n - k) k = n - k; /* use smaller k */
    uint32_t result = 1;
    uint32_t i;
    for (i = 0; i < k; i++) {
        /* Multiply (n - i) / (i + 1) step-by-step to stay exact */
        result = result * (n - i) / (i + 1);
    }
    return result;
}

/* Ballot number: number of ways candidate A (with a votes) is strictly
 * ahead of B (with b votes) throughout the count. a > b required.
 * Formula: B(a,b) = C(a+b, b) - C(a+b, b-1)  (reflection principle)
 * When b==0: B(a,0) = C(a,0) = 1 (trivially, no B votes means A always leads)
 */
static uint32_t ballot_number(uint32_t a, uint32_t b) {
    if (b == 0) return 1;
    if (a <= b) return 0;
    uint32_t total = a + b;
    return comb(total, b) - comb(total, b - 1);
}

void _start(void) {
    /* Compute ballot numbers for several (a, b) pairs */
    uint32_t pairs[8][2] = {
        {3, 1}, {4, 1}, {4, 2}, {5, 1},
        {5, 2}, {5, 3}, {6, 2}, {6, 3}
    };
    uint32_t sum = 0;
    uint32_t xor_acc = 0;
    uint32_t i;
    for (i = 0; i < 8; i++) {
        uint32_t bn = ballot_number(pairs[i][0], pairs[i][1]);
        sum += bn;
        xor_acc ^= bn;
    }

    uint32_t n_tests  = 8;
    uint32_t metric_a = sum & 0xFF;        /* sum of ballot numbers mod 256 */
    uint32_t metric_b = xor_acc & 0xFF;   /* XOR of ballot numbers mod 256 */

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;

    while (1) {}
}
