/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — 2D Binary Indexed Tree (2D Fenwick) fixture.
 *
 * Extends the 1D BIT to 2 dimensions.  Both update and query loop over two
 * independent BIT traversals (nested loops).
 *
 * Distinctive decompiler idioms:
 *   1. `for (i=x; i<=N; i+=i&(-i))` — outer BIT traversal for update
 *   2. `for (j=y; j<=M; j+=j&(-j))` — inner BIT traversal for update
 *   3. `for (i=x; i>0; i-=i&(-i))` — outer BIT traversal for query
 *   4. `for (j=y; j>0; j-=j&(-j))` — inner BIT traversal for query
 *   5. `bit2[i][j] += v` — 2D cell update (vs 1D `bit[i] += v`)
 *
 * Updates: (1,1)+=5, (2,3)+=3, (3,2)+=7, (4,4)+=2
 * Queries:
 *   prefix_sum(3,3) = 5+3+7 = 15   [excludes (4,4)]
 *   prefix_sum(4,4) = 5+3+7+2 = 17 [all cells]
 *
 * n_updates = 4  = 0x04
 * q33       = 15 = 0x0F
 * q44       = 17 = 0x11
 *
 * g_result = (n_updates << 16) | (q33 << 8) | q44 = 0x040F11
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BIT2_N 5
#define BIT2_M 5

static int bit2_arr[BIT2_N + 1][BIT2_M + 1];

static void bit2_update(int x, int y, int v)
{
    for (int i = x; i <= BIT2_N; i += i & (-i))
        for (int j = y; j <= BIT2_M; j += j & (-j))
            bit2_arr[i][j] += v;
}

static int bit2_query(int x, int y)
{
    int s = 0;
    for (int i = x; i > 0; i -= i & (-i))
        for (int j = y; j > 0; j -= j & (-j))
            s += bit2_arr[i][j];
    return s;
}

void test_2d_fenwick(void)
{
    bit2_update(1, 1, 5);
    bit2_update(2, 3, 3);
    bit2_update(3, 2, 7);
    bit2_update(4, 4, 2);

    int q33 = bit2_query(3, 3);  /* 5+3+7 = 15 */
    int q44 = bit2_query(4, 4);  /* 5+3+7+2 = 17 */

    g_result = ((uint32_t)4   << 16)
             | ((uint32_t)q33 << 8)
             | ((uint32_t)q44 & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_2d_fenwick();
    for (;;);
}
