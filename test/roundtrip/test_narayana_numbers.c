/* test_narayana_numbers.c
 * Narayana numbers N(n,k) count Dyck paths of semi-length n with exactly k peaks.
 *
 * Formula: N(n,k) = (1/n) * C(n,k) * C(n,k-1)
 *
 * For small n (1..8) the values fit in 32 bits (max N(8,4)=490).
 * We compute C(n,k) via Pascal's triangle (no division, no 64-bit helpers).
 * N(n,k) = C(n,k) * C(n,k-1) / n  — integer division exact for these small n.
 *
 * Properties verified:
 *  - N(n,1) = 1 for all n >= 1
 *  - N(n,n) = 1 for all n >= 1
 *  - sum_{k=1}^{n} N(n,k) = Catalan(n)
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Pascal's triangle for n up to 10 */
static uint32_t C[11][11]; /* C[n][k] */

static void build_pascal(void)
{
    for (uint32_t n = 0; n <= 10; n++) {
        C[n][0] = 1;
        for (uint32_t k = 1; k <= n; k++)
            C[n][k] = C[n-1][k-1] + C[n-1][k];
        for (uint32_t k = n+1; k <= 10; k++)
            C[n][k] = 0;
    }
}

/* N(n,k) for 1 <= k <= n, exact integer result for n <= 8 */
static uint32_t narayana(uint32_t n, uint32_t k)
{
    if (k == 0 || k > n) return 0;
    return (C[n][k] * C[n][k-1]) / n;
}

/* Catalan(n) = C(2n,n)/(n+1) for small n — precomputed */
static const uint32_t catalan[9] = {1, 1, 2, 5, 14, 42, 132, 429, 1430};

static void run_narayana(void)
{
    build_pascal();

    uint32_t n_tests = 8u;
    uint32_t edge_ok = 0;    /* count of N(n,1)==1 and N(n,n)==1 */
    uint32_t catalan_ok = 0; /* count of rows whose sum equals Catalan(n) */
    uint32_t xor_acc = 0;

    for (uint32_t n = 1; n <= n_tests; n++) {
        uint32_t row_sum = 0;
        for (uint32_t k = 1; k <= n; k++) {
            uint32_t v = narayana(n, k);
            row_sum += v;
            xor_acc ^= v;
            if (k == 1 && v == 1) edge_ok++;
            if (k == n && v == 1) edge_ok++;
        }
        if (row_sum == catalan[n]) catalan_ok++;
    }

    /* edge_ok == 16 (2 per row * 8 rows), catalan_ok == 8 */
    uint32_t metric_a = edge_ok & 0xFFu;       /* 0x10 = 16 */
    uint32_t metric_b = catalan_ok & 0xFFu;    /* 0x08 = 8  */
    if (metric_a == 0) metric_a = 0x4Au;
    if (metric_b == 0) metric_b = 0x2Eu;
    if (metric_a == metric_b) metric_b ^= 0x13u;
    (void)xor_acc;
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void)
{
    run_narayana();
    while (1) {}
}
