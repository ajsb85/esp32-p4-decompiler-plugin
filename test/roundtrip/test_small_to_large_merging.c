/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Small-to-Large Merging (DSU on tree) fixture.
 *
 * Small-to-large merging (also called "weighted union" or "DSU on tree"):
 * When merging two sets, always iterate over the smaller set and insert its
 * elements into the larger set.  This gives O(n log n) total work.
 *
 * Here we simulate merging multisets stored as frequency arrays.
 * Starting with n singleton sets {0},{1},...,{n-1}, we merge them in a
 * tree structure and track the maximum frequency at each merge step.
 *
 * Distinctive decompiler idioms:
 *   1. Size-check swap: `if (sz[a] < sz[b]) { swap(a,b); }` before merge
 *   2. Element rehash: `for each elem in small_set: insert into large_set`
 *   3. Frequency increment: `freq[large][elem]++; if (freq>max) max=freq`
 *   4. Union-find path compression: `while (par[x]!=x) x=par[x]=par[par[x]]`
 *   5. Size update: `sz[large] += sz[small]`
 *
 * Tree merges (4 nodes: 0,1,2,3):
 *   Merge {0} into {1}  → {0,1}, max_freq=1
 *   Merge {2} into {3}  → {2,3}, max_freq=1
 *   Merge {0,1} into {2,3} → {0,1,2,3}, max_freq=1
 *   Then insert element 1 again into the merged set → freq[1]=2, max_freq=2
 *
 * n_merges     = 4   (0x04)
 * final_size   = 4   (0x04)
 * max_freq     = 2   (0x02)
 *
 * g_result = (n_merges<<16)|(final_size<<8)|max_freq = 0x040402
 */
#include <stdint.h>

volatile uint32_t g_result;

#define STL_N    8    /* max elements in universe */
#define STL_SETS 8    /* max sets */

/* DSU (union-find) with size for small-to-large */
static uint32_t stl_par[STL_SETS];
static uint32_t stl_sz[STL_SETS];

/* Frequency table: freq[set_root][element] */
static uint32_t stl_freq[STL_SETS][STL_N];

/* Elements list per set (for iteration during merge) */
static uint32_t stl_elems[STL_SETS][STL_N];
static uint32_t stl_nelem[STL_SETS];

static uint32_t stl_max_freq;

static uint32_t stl_find(uint32_t x)
{
    while (stl_par[x] != x) {
        stl_par[x] = stl_par[stl_par[x]]; /* path compression */
        x = stl_par[x];
    }
    return x;
}

/* Merge set b INTO set a (small-to-large: caller ensures sz[a] >= sz[b]) */
static void stl_merge_into(uint32_t a, uint32_t b)
{
    /* Iterate over smaller set b, insert into a */
    for (uint32_t i = 0; i < stl_nelem[b]; i++) {
        uint32_t elem = stl_elems[b][i];
        stl_freq[a][elem] += stl_freq[b][elem];
        stl_elems[a][stl_nelem[a]++] = elem;
        if (stl_freq[a][elem] > stl_max_freq)
            stl_max_freq = stl_freq[a][elem];
    }
    stl_sz[a] += stl_sz[b];
    stl_par[b] = a;
}

/* Union with small-to-large heuristic */
static void stl_union(uint32_t x, uint32_t y)
{
    uint32_t rx = stl_find(x), ry = stl_find(y);
    if (rx == ry) return;
    /* Always merge smaller into larger */
    if (stl_sz[rx] < stl_sz[ry]) {
        uint32_t tmp = rx; rx = ry; ry = tmp;
    }
    stl_merge_into(rx, ry);
}

/* Insert element e into the set containing node x */
static void stl_insert(uint32_t x, uint32_t e)
{
    uint32_t rx = stl_find(x);
    stl_freq[rx][e]++;
    /* Add to element list only if first occurrence in this set */
    if (stl_freq[rx][e] == 1) {
        stl_elems[rx][stl_nelem[rx]++] = e;
    }
    if (stl_freq[rx][e] > stl_max_freq)
        stl_max_freq = stl_freq[rx][e];
}

void test_small_to_large_merging(void)
{
    /* Initialise: 4 singleton sets {0},{1},{2},{3} */
    for (uint32_t i = 0; i < 4; i++) {
        stl_par[i]     = i;
        stl_sz[i]      = 1;
        stl_nelem[i]   = 1;
        stl_elems[i][0] = i;
        stl_freq[i][i] = 1;
    }
    stl_max_freq = 1;

    uint32_t n_merges = 0;

    stl_union(0, 1); n_merges++;  /* {0,1}    size=2 */
    stl_union(2, 3); n_merges++;  /* {2,3}    size=2 */
    stl_union(0, 2); n_merges++;  /* {0,1,2,3} size=4 */

    /* Insert element 1 again (duplicate) — bumps freq[1] to 2 */
    stl_insert(0, 1); n_merges++;

    uint32_t root      = stl_find(0);
    uint32_t final_sz  = stl_sz[root]; /* expect 4 */
    /* max_freq = 2 (element 1 appears twice) */

    g_result = (n_merges << 16) | ((final_sz & 0xFFu) << 8) | (stl_max_freq & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_small_to_large_merging();
    for (;;);
}
