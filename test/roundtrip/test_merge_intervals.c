/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Merge Intervals fixture.
 *
 * Merges overlapping intervals from a sorted list:
 * push first interval to result; for each next interval:
 *   if it overlaps with last in result, extend; else append new.
 *
 * Distinctive decompiler idioms:
 *   1. `if (intervals[i].start <= result.back().end)` — overlap check
 *   2. `result.back().end = max(result.back().end, intervals[i].end)` — merge
 *   3. Input assumed sorted by start time
 *
 * Test cases (3 sorted interval sets):
 *   {(1,3),(2,6),(8,10),(15,18)} → {(1,6),(8,10),(15,18)} → 3 merged
 *   {(1,4),(4,5)}                → {(1,5)}                → 1 merged
 *   {(1,3),(4,6),(8,10)}         → no merge               → 3 merged
 *   sum=3+1+3=7=0x07, xor=3^1^3=1=0x01
 *
 * g_result = (3 << 16) | (7 << 8) | 1 = 0x00030701
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MI_MAX 4

typedef struct { int s, e; } Ivl;

static Ivl mi_res[MI_MAX];

static int merge_ivl(const Ivl *iv, int n)
{
    if (n == 0) return 0;
    int cnt = 0;
    mi_res[0] = iv[0];
    cnt = 1;
    for (int i = 1; i < n; i++) {
        if (iv[i].s <= mi_res[cnt-1].e) {
            if (iv[i].e > mi_res[cnt-1].e)
                mi_res[cnt-1].e = iv[i].e;
        } else {
            mi_res[cnt++] = iv[i];
        }
    }
    return cnt;
}

void test_merge_intervals(void)
{
    static const Ivl iv0[4] = {{1,3},{2,6},{8,10},{15,18}};
    static const Ivl iv1[2] = {{1,4},{4,5}};
    static const Ivl iv2[3] = {{1,3},{4,6},{8,10}};

    int r0 = merge_ivl(iv0, 4); /* 3 */
    int r1 = merge_ivl(iv1, 2); /* 1 */
    int r2 = merge_ivl(iv2, 3); /* 3 */

    g_result = (3u << 16)
             | ((uint32_t)((r0 + r1 + r2) & 0xFF) << 8)
             | ((uint32_t)((r0 ^ r1 ^ r2) & 0xFF));
}

__attribute__((noreturn)) void _start(void)
{
    test_merge_intervals();
    for (;;);
}
