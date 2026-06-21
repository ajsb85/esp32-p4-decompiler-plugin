/* test_bell_numbers.c
 * Bell numbers B(n) count the number of partitions of a set of n elements.
 * Computed via the Bell triangle (Aitken's array):
 *   Row 0: [1]
 *   Each subsequent row starts with the last element of the previous row,
 *   then each next element is sum of left neighbor and element directly
 *   above the left neighbor.
 *   B(n) is the first element of row n (= last element of row n-1).
 *
 * B(0)=1, B(1)=1, B(2)=2, B(3)=5, B(4)=15, B(5)=52,
 * B(6)=203, B(7)=877, B(8)=4140, B(9)=21147 (mod BMOD)
 *
 * All arithmetic kept 32-bit (values mod 10^9+7).
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BMOD 1000000007u
#define BELL_MAX 10u

/* Bell triangle row storage (only need two rows at a time) */
static uint32_t bell_row[BELL_MAX + 1];
static uint32_t bell_prev[BELL_MAX + 1];

static uint32_t compute_bell(uint32_t n)
{
    if (n == 0) return 1;
    /* Initialize row 0 */
    bell_row[0] = 1;
    for (uint32_t r = 1; r <= n; r++) {
        /* New row starts with last element of previous row */
        bell_prev[0] = bell_row[r - 1];
        for (uint32_t c = 1; c <= r; c++) {
            bell_prev[c] = (bell_prev[c-1] + bell_row[c-1]) % BMOD;
        }
        /* Copy bell_prev into bell_row for next iteration */
        for (uint32_t c = 0; c <= r; c++) {
            bell_row[c] = bell_prev[c];
        }
    }
    return bell_row[0]; /* first element of row n = B(n) */
}

static void run_bell_numbers(void)
{
    /* Compute B(0)..B(9) and verify known values */
    /* Known: 1,1,2,5,15,52,203,877,4140,21147 */
    uint32_t known[10] = {1,1,2,5,15,52,203,877,4140,21147};
    uint32_t n_tests = 10;
    uint32_t match_count = 0;
    uint32_t xor_acc = 0;

    for (uint32_t i = 0; i < n_tests; i++) {
        uint32_t b = compute_bell(i);
        xor_acc ^= b;
        if (b == known[i]) match_count++;
    }

    /* match_count == n_tests == 10 if all correct */
    uint32_t metric_a = match_count & 0xFFu;         /* 0x0A = 10 */
    uint32_t metric_b = (xor_acc ^ (xor_acc >> 16)) & 0xFFu;
    if (metric_a == 0) metric_a = 0x42u;
    if (metric_b == 0) metric_b = 0x1Du;
    if (metric_a == metric_b) metric_b ^= 0x21u;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void)
{
    run_bell_numbers();
    while (1) {}
}
