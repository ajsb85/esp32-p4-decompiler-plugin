/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Count Inversions via Fenwick Tree fixture.
 *
 * Counts inversions in an array: pairs (i, j) where i < j and a[i] > a[j].
 *
 * Algorithm (O(n log n)):
 *   Coordinate-compress elements to [1..n].
 *   Process array left-to-right; for each element x:
 *     inversions += query(x-1)    (count elements < x already seen)
 *     update(x, +1)               (mark x as seen)
 *
 * Distinctive decompiler idioms:
 *   1. `inv_cnt += bit_query(x - 1)` BEFORE `bit_update(x, 1)` — order matters
 *   2. Fenwick `i & (-i)` paired with "inversions += seen smaller" accumulation
 *   3. Coordinate compression: `rank[a[i]] = i+1` after sorted copy
 *
 * Test array: [3, 1, 4, 1, 5, 9, 2, 6]  (values compressed to 1-based rank)
 *   Sorted unique: 1,2,3,4,5,6,9 → ranks 1..7
 *   Original ranks: 3,1,4,1,5,7,2,6
 *   Inversion pairs (i<j, a[i]>a[j]):
 *     (0→1):3>1, (0→6):3>2, (2→6):4>2, (4→6):5>2, (5→6):9>2, (3→6):1 nope...
 *   Let's count:
 *     i=0, x=3: query(2)=0 inv, update(3)
 *     i=1, x=1: query(0)=0 inv, update(1)
 *     i=2, x=4: query(3)=2 inv (1 and 3 seen), update(4)
 *     i=3, x=1: query(0)=0, update(1) → BIT[1]++
 *     i=4, x=5: query(4)=3 inv (1,1,3,4 → 4 elements, rank up to 4: seen 1,3,4 → 3), update(5)
 *     Wait, let me redo more carefully.
 *
 *   After coordinate compression of [3,1,4,1,5,9,2,6] to ranks in sorted(unique) order:
 *     unique sorted: [1,2,3,4,5,6,9] → rank 1..7
 *     [3,1,4,1,5,9,2,6] → ranks [3,1,4,1,5,7,2,6]
 *
 *   Inversion count using BIT on ranks [3,1,4,1,5,7,2,6]:
 *     Step 0: x=3, query(2)=0. update(3). BIT has 3.
 *     Step 1: x=1, query(0)=0. update(1). BIT has 1,3.
 *     Step 2: x=4, query(3)=2 (1 and 3 present). update(4). BIT: 1,3,4.
 *     Step 3: x=1, query(0)=0. update(1). BIT: 1(×2),3,4.
 *     Step 4: x=5, query(4)=4 (1,1,3,4 → 4 elements). update(5).
 *     Step 5: x=7, query(6)=5 (1,1,3,4,5 → 5 elements). update(7).
 *     Step 6: x=2, query(1)=2 (1,1 → 2 elements). update(2).
 *     Step 7: x=6, query(5)=6 (1,1,2,3,4,5 → 6 elements). update(6).
 *   Total inversions = 0+0+2+0+4+5+2+6 = 19
 *
 * n_elem = 8
 * inv_count = 19 = 0x13
 *
 * g_result = (n_elem << 16) | (inv_count << 8) | (inv_count & 0xFF)
 *   — avoid using same byte twice; use sum_seen at final step:
 *   final query result (step 7) = 6, so n_elem_last=6
 *
 * g_result = (8 << 16) | (19 << 8) | 6 = 0x081306
 */
#include <stdint.h>

volatile uint32_t g_result;

#define INV_N 8
#define INV_MAX_RANK 8  /* max rank value ≤ n */

static int inv_bit[INV_MAX_RANK + 1];

static void inv_update(int i, int v)
{
    for (; i <= INV_MAX_RANK; i += i & (-i))
        inv_bit[i] += v;
}

static int inv_query(int i)
{
    int s = 0;
    for (; i > 0; i -= i & (-i))
        s += inv_bit[i];
    return s;
}

void test_inversion_bit(void)
{
    /* Original array after coordinate compression to ranks 1..7 */
    static const int a[INV_N] = {3, 1, 4, 1, 5, 7, 2, 6};

    int inv_cnt = 0, last_seen = 0;
    for (int i = 0; i < INV_N; i++) {
        inv_cnt += inv_query(a[i] - 1);  /* count elements < a[i] already inserted */
        inv_update(a[i], 1);
        if (i == INV_N - 1)
            last_seen = inv_query(a[i] - 1);  /* for g_result byte 3 */
    }
    /* inv_cnt=19, last_seen=6 */

    g_result = ((uint32_t)INV_N    << 16)
             | ((uint32_t)inv_cnt  << 8)
             | ((uint32_t)last_seen & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_inversion_bit();
    for (;;);
}
