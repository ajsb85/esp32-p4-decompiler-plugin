/* test_golomb_sequence.c
 * Golomb's self-describing sequence: a(1)=1, and a(n) is the number of times
 * n appears in the sequence.  Formula: a(1)=1, a(2)=2, and
 *   a(n) = 1 + a(n - a(a(n-1)))   for n >= 2  (recursive, but we iterate).
 * First values: 1,2,2,3,3,4,4,4,5,5,5,6,6,6,6,...
 * We generate the first N terms iteratively.
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_golomb_sequence.c
 */
#include <stdint.h>

volatile uint32_t g_result;

#define GOLOMB_N 32U

static uint32_t golomb_seq[GOLOMB_N + 1];  /* 1-indexed: golomb_seq[1..N] */

/* Build Golomb sequence up to index n (1-based). */
static void golomb_build(uint32_t n) {
    uint32_t i;
    golomb_seq[1] = 1;
    if (n < 2) return;
    golomb_seq[2] = 2;
    for (i = 3; i <= n; i++) {
        /* a(i) = 1 + a(i - a(a(i-1))) */
        uint32_t inner = golomb_seq[i - 1];           /* a(i-1) */
        if (inner > i - 1) inner = i - 1;            /* safety clamp */
        uint32_t outer = golomb_seq[inner];           /* a(a(i-1)) */
        uint32_t idx = i - outer;
        if (idx < 1) idx = 1;
        golomb_seq[i] = 1 + golomb_seq[idx];
    }
}

/* Count how many terms equal a given value v. */
static uint32_t golomb_count_value(uint32_t v, uint32_t n) {
    uint32_t count = 0;
    uint32_t i;
    for (i = 1; i <= n; i++) {
        if (golomb_seq[i] == v) count++;
    }
    return count;
}

void _start(void) {
    golomb_build(GOLOMB_N);

    uint32_t xor_acc = 0;
    uint32_t sum = 0;
    uint32_t i;
    for (i = 1; i <= GOLOMB_N; i++) {
        xor_acc ^= golomb_seq[i];
        sum = (sum + golomb_seq[i]) % 256U;
    }

    /* Self-describing check: value v should appear exactly golomb_seq[v] times */
    uint32_t correct = 0;
    for (i = 1; i <= 8; i++) {  /* check first 8 distinct values */
        if (golomb_count_value(i, GOLOMB_N) == golomb_seq[i]) correct++;
    }

    uint32_t n_tests  = 32;              /* terms generated */
    uint32_t metric_a = (sum + correct) & 0xFF;
    uint32_t metric_b = xor_acc & 0xFF;

    if (metric_a == 0) metric_a = 1;
    if (metric_b == 0) metric_b = 2;
    if (metric_a == n_tests) metric_a = (metric_a + 1) & 0xFF;
    if (metric_b == n_tests || metric_b == metric_a) metric_b = (metric_b + 3) & 0xFF;
    if (metric_b == 0) metric_b = 7;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;

    while (1) {}
}
