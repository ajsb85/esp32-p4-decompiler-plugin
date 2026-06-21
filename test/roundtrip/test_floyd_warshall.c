/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Floyd-Warshall all-pairs shortest paths fixture.
 *
 * The triple nested loop (k, i, j) relaxation is one of the most distinctive
 * decompiler idioms in graph algorithms.
 *
 * Directed weighted 4-node graph:
 *   0→1 (3),  0→3 (5)
 *   1→0 (2),  1→3 (4)
 *   2→1 (1)
 *   3→2 (2)
 *
 * Initial distance matrix (INF = 0x3FFF):
 *   d = { {0,3,INF,5}, {2,0,INF,4}, {INF,1,0,INF}, {INF,INF,2,0} }
 *
 * After Floyd-Warshall:
 *   d = { {0, 3, 7, 5},
 *         {2, 0, 6, 4},
 *         {3, 1, 0, 5},
 *         {5, 3, 2, 0} }
 *
 * Sum of all off-diagonal entries: 3+7+5+2+6+4+3+1+5+5+3+2 = 46 = 0x2E
 * XOR of all off-diagonal entries: 3^7^5^2^6^4^3^1^5^5^3^2 = 2
 * n = 4
 *
 * g_result = (n << 16) | (sum << 8) | xor = 0x00042E02
 *
 * Recognizable decompiler idioms:
 *   for (k=0; k<N; k++)           ← intermediate-node loop
 *     for (i=0; i<N; i++)
 *       for (j=0; j<N; j++)
 *         if (d[i][k]+d[k][j] < d[i][j])  ← relaxation with 2D array access
 *           d[i][j] = d[i][k]+d[k][j];
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Graph ────────────────────────────────────────────────────────────────── */

#define FW_N   4
#define FW_INF 0x3FFF

static int fw_d[FW_N][FW_N];

static const int fw_init[FW_N][FW_N] = {
    {0,       3,      FW_INF, 5},
    {2,       0,      FW_INF, 4},
    {FW_INF,  1,      0,      FW_INF},
    {FW_INF,  FW_INF, 2,      0},
};

/* ── Floyd-Warshall ───────────────────────────────────────────────────────── */

static void floyd_warshall(void)
{
    for (int i = 0; i < FW_N; i++)
        for (int j = 0; j < FW_N; j++)
            fw_d[i][j] = fw_init[i][j];

    for (int k = 0; k < FW_N; k++) {
        for (int i = 0; i < FW_N; i++) {
            for (int j = 0; j < FW_N; j++) {
                if (fw_d[i][k] < FW_INF && fw_d[k][j] < FW_INF) {
                    int via_k = fw_d[i][k] + fw_d[k][j];
                    if (via_k < fw_d[i][j])
                        fw_d[i][j] = via_k;
                }
            }
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_floyd_warshall(void)
{
    floyd_warshall();

    uint32_t sum_d = 0, xor_d = 0;
    for (int i = 0; i < FW_N; i++) {
        for (int j = 0; j < FW_N; j++) {
            if (i != j && fw_d[i][j] < FW_INF) {
                sum_d += (uint32_t)fw_d[i][j];
                xor_d ^= (uint32_t)fw_d[i][j];
            }
        }
    }

    g_result = ((uint32_t)FW_N << 16)
             | (sum_d << 8)
             | (xor_d & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_floyd_warshall();
    for (;;);
}
