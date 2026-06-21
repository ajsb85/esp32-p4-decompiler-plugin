/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Binary Indexed Tree (Fenwick tree, 2D) fixture.
 *
 * Two-dimensional Fenwick tree supporting:
 *   - Point update: add value at (x, y)
 *   - Rectangle prefix query: sum over [1..x][1..y]
 *
 * 2D Fenwick update: `for (i=x; i<=N; i+=i&(-i)) for (j=y; j<=N; j+=j&(-j))`
 * 2D Fenwick query:  `for (i=x; i>0; i-=i&(-i)) for (j=y; j>0; j-=j&(-j))`
 *
 * Distinctive decompiler idioms:
 *   1. `i & (-i)` — isolate lowest set bit (Fenwick step)
 *   2. Nested doubly-indexed BIT loops with the same `i&-i` pattern
 *   3. Signed/unsigned interplay in the subtraction step
 *
 * Test on a 4×4 grid (indices 1..4):
 *   point_add(1,1,  5)
 *   point_add(2,3,  3)
 *   point_add(3,2,  7)
 *   point_add(4,4,  2)
 *
 * Prefix queries:
 *   query(4,4) = 5+3+7+2 = 17   (entire grid)
 *   query(2,3) = 5+3    = 8     (only (1,1) and (2,3) are within [1..2][1..3])
 *   query(3,2) = 5+7    = 12    (within [1..3][1..2]: (1,1) and (3,2))
 *
 * total  = 17 = 0x11
 * partial_a = 8  = 0x08
 * partial_b = 12 = 0x0C
 *
 * g_result = (total << 16) | (partial_a << 8) | partial_b = 0x0011080C
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BIT2_N 4

static int bit2[BIT2_N + 1][BIT2_N + 1];

static void bit2_update(int x, int y, int v)
{
    for (int i = x; i <= BIT2_N; i += i & (-i))
        for (int j = y; j <= BIT2_N; j += j & (-j))
            bit2[i][j] += v;
}

static int bit2_query(int x, int y)
{
    int s = 0;
    for (int i = x; i > 0; i -= i & (-i))
        for (int j = y; j > 0; j -= j & (-j))
            s += bit2[i][j];
    return s;
}

void test_binary_indexed(void)
{
    bit2_update(1, 1, 5);
    bit2_update(2, 3, 3);
    bit2_update(3, 2, 7);
    bit2_update(4, 4, 2);

    int total     = bit2_query(4, 4);  /* 17 */
    int partial_a = bit2_query(2, 3);  /* 8  */
    int partial_b = bit2_query(3, 2);  /* 12 */

    g_result = ((uint32_t)total     << 16)
             | ((uint32_t)partial_a << 8)
             | ((uint32_t)partial_b & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_binary_indexed();
    for (;;);
}
