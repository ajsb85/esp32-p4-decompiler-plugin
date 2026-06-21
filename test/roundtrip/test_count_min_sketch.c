/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Count-Min Sketch Frequency Estimation fixture.
 *
 * Count-Min Sketch is a space-efficient probabilistic data structure for
 * estimating frequencies of items in a stream.  It uses k hash functions,
 * each mapping to a table of size m.  The frequency estimate is the minimum
 * across all k hash tables.
 *
 * Distinctive decompiler idioms:
 *   1. `for (i=0; i<CMS_K; i++) cms_table[i][hash_i(x)]++` — parallel hashing update
 *   2. `min = cms_table[0][hash_0(x)]; for (i=1; ...) min = min(min, cms_table[i][...])` — min query
 *   3. `(a*x + b) % m` — simple linear hash function
 *   4. k independent hash functions, k separate table rows
 *   5. `+CMS_M) % CMS_M` — non-negative modulo idiom
 *
 * Parameters: k=3 hash functions, m=8 table size
 * Hash functions: h_i(x) = (a_i*x + b_i) % 8
 *   a = {3,5,7}, b = {1,3,5}
 *
 * Stream: {1,1,1,2,2,3}  (n=6 total inserts)
 * True frequencies: freq[1]=3, freq[2]=2, freq[3]=1
 * Queries (estimated min): q[1]=3, q[2]=2
 *
 * n_items = 6  = 0x06
 * q[1]    = 3  = 0x03
 * q[2]    = 2  = 0x02
 *
 * g_result = (n_items << 16) | (q1 << 8) | q2 = 0x060302
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CMS_K 3
#define CMS_M 8

static int cms_table[CMS_K][CMS_M];
static const int cms_a[CMS_K] = {3, 5, 7};
static const int cms_b[CMS_K] = {1, 3, 5};

static int cms_hash(int i, int x)
{
    return ((cms_a[i] * x + cms_b[i]) % CMS_M + CMS_M) % CMS_M;
}

static void cms_update(int x)
{
    for (int i = 0; i < CMS_K; i++)
        cms_table[i][cms_hash(i, x)]++;
}

static int cms_query(int x)
{
    int mn = cms_table[0][cms_hash(0, x)];
    for (int i = 1; i < CMS_K; i++) {
        int v = cms_table[i][cms_hash(i, x)];
        if (v < mn) mn = v;
    }
    return mn;
}

void test_count_min_sketch(void)
{
    static const int items[6] = {1, 1, 1, 2, 2, 3};
    for (int i = 0; i < 6; i++) cms_update(items[i]);

    int q1 = cms_query(1);  /* = 3 */
    int q2 = cms_query(2);  /* = 2 */

    g_result = ((uint32_t)6  << 16)
             | ((uint32_t)q1 << 8)
             | ((uint32_t)q2 & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_count_min_sketch();
    for (;;);
}
