/* test_euler_zigzag.c
 * Purpose   : Euler zigzag numbers (alternating permutation counts) via the
 *             Entringer triangle recurrence.
 *
 * Algorithm : Entringer numbers E(n,k):
 *               E(0,0) = 1
 *               E(n,0) = 0  for n >= 1
 *               E(n,k) = E(n,k-1) + E(n-1, n-k)  for k >= 1
 *             The n-th zigzag number is E(n,n).
 *
 * Known values: E(0)=1, E(1)=1, E(2)=1, E(3)=2, E(4)=5, E(5)=16, E(6)=61
 *
 * Distinctive decompiler idioms:
 *   1. 2-D triangle fill: `T[n][k] = T[n][k-1] + T[n-1][n-k]`
 *   2. Diagonal extraction: `zigzag[n] = T[n][n]`
 *   3. Accumulate odd-indexed entries: E(1)+E(3)+E(5) = 1+2+16 = 19
 *
 * n_tests  = 7   (E(0)..E(6))   (0x07)
 * odd_sum  = 19                  (0x13)
 * max_val  = 61                  (0x3D)
 *
 * g_result = (n_tests<<16) | (odd_sum<<8) | max_val = 0x07133D
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define EZ_N 7u   /* compute E(0)..E(6) */

/* Entringer triangle: T[n][k], n and k in [0, EZ_N) */
static uint32_t ez_T[EZ_N][EZ_N];
static uint32_t ez_zigzag[EZ_N];

void test_euler_zigzag(void)
{
    /* Initialise triangle */
    for (uint32_t i = 0u; i < EZ_N; i++)
        for (uint32_t j = 0u; j < EZ_N; j++)
            ez_T[i][j] = 0u;

    ez_T[0][0] = 1u;
    ez_zigzag[0] = 1u;

    for (uint32_t n = 1u; n < EZ_N; n++) {
        ez_T[n][0] = 0u;  /* E(n,0) = 0 for n >= 1 */
        for (uint32_t k = 1u; k <= n; k++) {
            ez_T[n][k] = ez_T[n][k - 1u] + ez_T[n - 1u][n - k];
        }
        ez_zigzag[n] = ez_T[n][n];
    }

    /* Compute metrics */
    uint32_t odd_sum = 0u;
    uint32_t max_val = 0u;
    for (uint32_t i = 0u; i < EZ_N; i++) {
        if (ez_zigzag[i] > max_val) max_val = ez_zigzag[i];
        if ((i & 1u) != 0u) odd_sum += ez_zigzag[i];
    }
    /* odd_sum = E(1)+E(3)+E(5) = 1+2+16 = 19 = 0x13; max_val=61=0x3D */
    g_result = (EZ_N << 16) | ((odd_sum & 0xFFu) << 8) | (max_val & 0xFFu);
}

void _start(void)
{
    test_euler_zigzag();
    while (1) {}
}
