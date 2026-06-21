/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Matrix Rank over GF(2) (Gaussian Elimination) fixture.
 *
 * Gaussian elimination over GF(2) (binary field) uses XOR instead of
 * subtraction.  Rows are packed as integers; `row ^= pivot` eliminates a
 * column in all other rows.
 *
 * Distinctive decompiler idioms:
 *   1. `if ((m[row] >> col) & 1)` — test bit col in packed row
 *   2. `m[row] ^= m[rank]` — row elimination via XOR (not subtraction)
 *   3. `t = m[rank]; m[rank] = m[pivot]; m[pivot] = t` — row swap
 *   4. `rank++` only when a pivot is found (column is not all-zero)
 *   5. No division step (GF(2) has only 0 and 1 — no scaling needed)
 *
 * Matrix (5×5, rows packed as 5-bit integers, LSB = col 0):
 *   row0 = 0b10110 = 22   → cols {1,2,4}
 *   row1 = 0b01101 = 13   → cols {0,2,3}
 *   row2 = 0b11011 = 27   → cols {0,1,3,4}
 *   row3 = 0b10101 = 21   → cols {0,2,4}
 *   row4 = 0b01110 = 14   → cols {1,2,3}
 *
 * After elimination: rank = 3
 * (Rows 2 and 4 become zero; row space has dimension 3)
 * Checksum = (22+13+27+21+14) % 256 = 97 = 0x61
 *
 * n_rows    = 5  = 0x05
 * rank      = 3  = 0x03
 * checksum  = 97 = 0x61
 *
 * g_result = (n_rows << 16) | (rank << 8) | checksum = 0x050361
 */
#include <stdint.h>

volatile uint32_t g_result;

#define GF2_R 5
#define GF2_C 5

static uint8_t gf2_m[GF2_R];

static int gf2_rank(void)
{
    int rank = 0;
    for (int col = 0; col < GF2_C; col++) {
        int pivot = -1;
        for (int row = rank; row < GF2_R; row++) {
            if ((gf2_m[row] >> col) & 1u) { pivot = row; break; }
        }
        if (pivot < 0) continue;

        uint8_t t = gf2_m[rank]; gf2_m[rank] = gf2_m[pivot]; gf2_m[pivot] = t;
        for (int row = 0; row < GF2_R; row++) {
            if (row != rank && ((gf2_m[row] >> col) & 1u))
                gf2_m[row] ^= gf2_m[rank];
        }
        rank++;
    }
    return rank;
}

void test_matrix_rank_gf2(void)
{
    static const uint8_t init[GF2_R] = {22, 13, 27, 21, 14};
    for (int i = 0; i < GF2_R; i++) gf2_m[i] = init[i];

    int r = gf2_rank();  /* = 3 */

    int ck = 0;
    for (int i = 0; i < GF2_R; i++) ck += init[i];
    ck &= 0xFF;  /* = 97 */

    g_result = ((uint32_t)GF2_R << 16)
             | ((uint32_t)r     << 8)
             | ((uint32_t)ck & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_matrix_rank_gf2();
    for (;;);
}
