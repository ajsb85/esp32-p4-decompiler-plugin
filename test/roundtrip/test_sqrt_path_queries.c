/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Sqrt-Decomposition Path Queries on a tree.
 *
 * Sqrt decomposition on tree paths:
 *   Partition the heavy path into blocks of size ~sqrt(N).
 *   Each block stores the XOR of its node values.
 *   Path query: traverse the heavy path, use block XOR where whole block fits,
 *   or iterate node-by-node in partial blocks at the ends.
 *
 * Distinctive decompiler idioms:
 *   1. `block_id = depth[v] / BLOCK` — assign node to a sqrt block
 *   2. `if (l_block == r_block) { for v in [l..r] xor val[v] }` — partial block
 *   3. `for b in [l_block+1..r_block-1] ans ^= block_xor[b]` — whole-block XOR
 *   4. `block_xor[b] ^= new_val ^ old_val` — point update propagates to block
 *
 * Tree: path graph 1-2-3-4-5-6-7-8-9 (n=9), values = {3,5,7,11,13,17,19,23,29}
 * BLOCK = 3
 * Blocks: {0:[3,5,7], 1:[11,13,17], 2:[19,23,29]}
 * Block XORs: {0: 3^5^7=1, 1: 11^13^17=23, 2: 19^23^29=25}
 *
 * Queries (node indices 0-based):
 *   Q1: XOR[2..6] = 7^11^13^17^19 = 15     (partial block 0 right + full block 1 + partial block 2 left)
 *   Q2: XOR[0..8] = 3^5^7^11^13^17^19^23^29 = 1^23^25 = 15
 *
 * n_queries = 2, q1=15, q2=15
 * g_result = (n_queries<<16)|(q1<<8)|q2 = 0x020F0F
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SPQ_N      9
#define SPQ_BLOCK  3
#define SPQ_NBLK   3   /* ceil(9/3) */

static uint32_t spq_val[SPQ_N]  = {3,5,7,11,13,17,19,23,29};
static uint32_t spq_blk[SPQ_NBLK];

static void spq_build(void)
{
    for (int b = 0; b < SPQ_NBLK; b++) spq_blk[b] = 0;
    for (int i = 0; i < SPQ_N; i++)
        spq_blk[i / SPQ_BLOCK] ^= spq_val[i];
}

/* Range XOR query [l..r] using sqrt blocks */
static uint32_t spq_query(int l, int r)
{
    int lb = l / SPQ_BLOCK;
    int rb = r / SPQ_BLOCK;
    uint32_t ans = 0;
    if (lb == rb) {
        for (int i = l; i <= r; i++) ans ^= spq_val[i];
        return ans;
    }
    /* Left partial block */
    int lend = (lb + 1) * SPQ_BLOCK - 1;
    for (int i = l; i <= lend; i++) ans ^= spq_val[i];
    /* Full blocks */
    for (int b = lb + 1; b < rb; b++) ans ^= spq_blk[b];
    /* Right partial block */
    int rstart = rb * SPQ_BLOCK;
    for (int i = rstart; i <= r; i++) ans ^= spq_val[i];
    return ans;
}

void test_sqrt_path_queries(void)
{
    spq_build();
    uint32_t q1 = spq_query(2, 6);   /* 15 */
    uint32_t q2 = spq_query(0, 8);   /* 15 */
    g_result = (2u << 16) | ((q1 & 0xFFu) << 8) | (q2 & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_sqrt_path_queries();
    for (;;);
}
