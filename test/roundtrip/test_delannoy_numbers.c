/* test_delannoy_numbers.c
 * Delannoy numbers: D(m,n) = number of paths from (0,0) to (m,n)
 * using steps right (+1,0), up (0,+1), diagonal (+1,+1).
 * Recurrence: D(0,k)=D(k,0)=1, D(m,n)=D(m-1,n)+D(m,n-1)+D(m-1,n-1)
 * All arithmetic is 32-bit.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define DMAX 8

static uint32_t delannoy_table(uint32_t m, uint32_t n) {
    uint32_t dp[DMAX][DMAX];
    uint32_t i, j;
    for (i = 0; i < DMAX; i++) dp[i][0] = 1;
    for (j = 0; j < DMAX; j++) dp[0][j] = 1;
    for (i = 1; i <= m; i++) {
        for (j = 1; j <= n; j++) {
            dp[i][j] = dp[i-1][j] + dp[i][j-1] + dp[i-1][j-1];
        }
    }
    return dp[m][n];
}

static uint32_t delannoy_checksum(void) {
    /* Sum D(1,1)..D(4,4) mod 256 for a portable fingerprint */
    uint32_t s = 0;
    uint32_t m, n;
    for (m = 1; m <= 4; m++) {
        for (n = 1; n <= 4; n++) {
            s += delannoy_table(m, n);
        }
    }
    return s & 0xFF;
}

static void run_delannoy(void) {
    /* D(3,3) = 63, D(4,4) = 321 -> 321 & 0xFF = 65 */
    uint32_t d33 = delannoy_table(3, 3);   /* 63  */
    uint32_t d44 = delannoy_table(4, 4);   /* 321 -> 0x41 */
    uint32_t n_tests = 9;                  /* 3x3 grid of cells tested */
    uint32_t metric_a = d33 & 0xFF;        /* 0x3F */
    uint32_t metric_b = delannoy_checksum();/* non-zero & != metric_a */
    (void)d44;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    run_delannoy();
    while (1) {}
}
