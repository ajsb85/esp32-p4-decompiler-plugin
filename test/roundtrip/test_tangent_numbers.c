/* test_tangent_numbers.c
 * Purpose   : Tangent numbers T(2k+1) for k=0..3, computed via the Entringer
 *             triangle (same triangle as zigzag numbers, but odd-indexed diagonals).
 *
 * Algorithm : Entringer numbers E(n,k):
 *               E(0,0) = 1
 *               E(n,0) = 0  for n >= 1
 *               E(n,k) = E(n,k-1) + E(n-1, n-k)
 *             Tangent numbers: T(2k+1) = E(2k+1, 2k+1)
 *             So T(1)=1, T(3)=2, T(5)=16, T(7)=272.
 *
 * Distinctive decompiler idioms:
 *   1. Triangle recurrence: `T[n][k] = T[n][k-1] + T[n-1][n-k]`
 *   2. Extract odd-indexed diagonal entries only
 *   3. XOR accumulation of 4 growing values
 *
 * n_tan    = 4   (T(1), T(3), T(5), T(7))   (0x04)
 * sum_low  = (1+2+16+272) & 0xFF = 291 & 0xFF = 0x23
 * xor_low  = (1^2^16^272) & 0xFF = 259 & 0xFF = 0x03
 *
 * g_result = (n_tan<<16) | (sum_low<<8) | xor_low = 0x042303
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* We need E(7,7)=272; build Entringer triangle up to row 7 */
#define TAN_ROWS 8u   /* rows 0..7 */
#define TAN_N    4u   /* four tangent numbers: T(1),T(3),T(5),T(7) */

static uint32_t tan_E[TAN_ROWS][TAN_ROWS];
static uint32_t tan_vals[TAN_N];  /* T(1), T(3), T(5), T(7) */

void test_tangent_numbers(void)
{
    for (uint32_t i = 0u; i < TAN_ROWS; i++)
        for (uint32_t j = 0u; j < TAN_ROWS; j++)
            tan_E[i][j] = 0u;

    tan_E[0][0] = 1u;

    for (uint32_t n = 1u; n < TAN_ROWS; n++) {
        tan_E[n][0] = 0u;
        for (uint32_t k = 1u; k <= n; k++) {
            tan_E[n][k] = tan_E[n][k - 1u] + tan_E[n - 1u][n - k];
        }
    }

    /* Extract tangent numbers from odd-indexed rows: T(2k+1) = E(2k+1, 2k+1) */
    for (uint32_t k = 0u; k < TAN_N; k++) {
        uint32_t row = 2u * k + 1u;  /* rows 1, 3, 5, 7 */
        tan_vals[k] = tan_E[row][row];
    }
    /* tan_vals = {1, 2, 16, 272} */

    uint32_t sum_t = 0u;
    uint32_t xor_t = 0u;
    for (uint32_t k = 0u; k < TAN_N; k++) {
        sum_t += tan_vals[k];
        xor_t ^= tan_vals[k];
    }
    /* sum=291, sum&0xFF=0x23; xor=259, xor&0xFF=0x03 */
    g_result = (TAN_N << 16) | ((sum_t & 0xFFu) << 8) | (xor_t & 0xFFu);
}

void _start(void)
{
    test_tangent_numbers();
    while (1) {}
}
