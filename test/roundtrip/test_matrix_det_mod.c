/* test_matrix_det_mod.c
 * Determinant of a small integer matrix modulo a prime, using
 * Gaussian elimination with modular inverse (Fermat's little theorem).
 * MOD = 997 (prime < 1024), so products fit in 32 bits (997*997 < 2^20 < 2^32).
 * All arithmetic strictly 32-bit.
 */
#include <stdint.h>

#define MDM_N   3u
#define MDM_MOD 997u

volatile uint32_t g_result;

/* modular exponentiation: base^exp mod m  (all 32-bit, m < 2^16) */
static uint32_t mdm_powmod(uint32_t base, uint32_t exp, uint32_t m) {
    uint32_t result = 1u;
    base %= m;
    while (exp > 0u) {
        if (exp & 1u) {
            result = (result * base) % m;
        }
        base = (base * base) % m;
        exp >>= 1;
    }
    return result;
}

/* modular inverse via Fermat: a^(m-2) mod m */
static uint32_t mdm_inv(uint32_t a, uint32_t m) {
    return mdm_powmod(a % m, m - 2u, m);
}

static uint32_t mdm_det(void) {
    /* 3x3 matrix: [[2,3,1],[4,1,2],[3,5,6]]
     * Exact det = 2*(6-10) - 3*(24-6) + 1*(20-3)
     *           = 2*(-4) - 3*(18) + 1*(17)
     *           = -8 - 54 + 17 = -45
     * mod 997   = 997 - 45 = 952 */
    uint32_t mat[MDM_N][MDM_N] = {
        {2u, 3u, 1u},
        {4u, 1u, 2u},
        {3u, 5u, 6u}
    };

    uint32_t sign = 1u; /* 1 or MDM_MOD-1 representing -1 */

    for (uint32_t col = 0u; col < MDM_N; col++) {
        /* find pivot row */
        uint32_t pivot_row = MDM_N; /* sentinel for "not found" */
        for (uint32_t row = col; row < MDM_N; row++) {
            if (mat[row][col] != 0u) {
                pivot_row = row;
                break;
            }
        }
        if (pivot_row == MDM_N) return 0u; /* singular */

        if (pivot_row != col) {
            for (uint32_t k = 0u; k < MDM_N; k++) {
                uint32_t tmp       = mat[col][k];
                mat[col][k]        = mat[pivot_row][k];
                mat[pivot_row][k]  = tmp;
            }
            sign = (sign == 1u) ? (MDM_MOD - 1u) : 1u;
        }

        uint32_t inv_pivot = mdm_inv(mat[col][col], MDM_MOD);

        for (uint32_t row = col + 1u; row < MDM_N; row++) {
            uint32_t factor = (mat[row][col] * inv_pivot) % MDM_MOD;
            for (uint32_t k = col; k < MDM_N; k++) {
                uint32_t sub = (factor * mat[col][k]) % MDM_MOD;
                mat[row][k]  = (mat[row][k] + MDM_MOD - sub) % MDM_MOD;
            }
        }
    }

    /* det = sign * diagonal product mod MDM_MOD */
    uint32_t det = sign;
    for (uint32_t i = 0u; i < MDM_N; i++) {
        det = (det * mat[i][i]) % MDM_MOD;
    }
    return det;
}

void _start(void) {
    uint32_t det = mdm_det(); /* expected: 952 (= -45 mod 997) */

    uint32_t n_tests  = 3u;
    /* det & 0xFF: 952 & 0xFF = 0xB8 = 184, non-zero */
    uint32_t metric_a = det & 0xFFu;
    if (metric_a == 0u) metric_a = 0x5Au;
    /* secondary metric: MDM_N=3 << 4 | MDM_MOD low nibble */
    uint32_t metric_b = (MDM_N << 4) | (MDM_MOD & 0x0Fu); /* 0x35 = 53 */
    if (metric_b == 0u) metric_b = 0x35u;

    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    while (1) {}
}
