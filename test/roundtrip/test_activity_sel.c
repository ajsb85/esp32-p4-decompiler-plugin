/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Activity selection (greedy interval scheduling) fixture.
 *
 * Classic greedy algorithm: sort activities by finish time, then scan left-to-right
 * picking each activity whose start time is ≥ the last selected finish time.
 *
 * Distinctive decompiler idioms:
 *   1. Sort by end: if (acts[j].end > acts[j+1].end) swap (insertion/bubble)
 *   2. Greedy pick: if (acts[i].start >= last_end) { count++; last_end=acts[i].end; }
 *
 * Input (n=6 activities): {[1,2],[3,4],[0,6],[5,7],[8,9],[5,9]}
 *
 * Sorted by finish time: {[1,2],[3,4],[0,6],[5,7],[8,9],[5,9]}
 *   (already sorted)
 *
 * Greedy selection:
 *   Pick [1,2] → last_end=2, count=1
 *   Pick [3,4] → start=3≥2, last_end=4, count=2
 *   Skip [0,6] → start=0<4
 *   Pick [5,7] → start=5≥4, last_end=7, count=3
 *   Pick [8,9] → start=8≥7, last_end=9, count=4
 *   Skip [5,9] → start=5<9
 *
 *   count       = 4
 *   sum_end     = 2 + 4 + 7 + 9 = 22 = 0x16
 *   n_acts      = 6
 *
 * g_result = (n_acts << 16) | (count << 8) | (sum_end & 0xFF) = 0x00060416
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Activity selection ────────────────────────────────────────────────────── */

#define ACT_N 6

typedef struct { int start; int end; } Act;

static Act acts[ACT_N];

static void acts_sort_by_end(int n)
{
    for (int i = 1; i < n; i++) {
        Act key = acts[i];
        int j = i - 1;
        while (j >= 0 && acts[j].end > key.end) {
            acts[j + 1] = acts[j];
            j--;
        }
        acts[j + 1] = key;
    }
}

static int activity_select(int n, int *sum_end_out)
{
    int count    = 0;
    int last_end = -1;
    int sum_end  = 0;

    for (int i = 0; i < n; i++) {
        if (acts[i].start >= last_end) {
            count++;
            last_end  = acts[i].end;
            sum_end  += acts[i].end;
        }
    }
    *sum_end_out = sum_end;
    return count;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_activity_sel(void)
{
    static const Act src[ACT_N] = {
        {1,2}, {3,4}, {0,6}, {5,7}, {8,9}, {5,9}
    };
    for (int i = 0; i < ACT_N; i++) acts[i] = src[i];

    acts_sort_by_end(ACT_N);

    int sum_end;
    int cnt = activity_select(ACT_N, &sum_end);   /* = 4, sum=22 */

    g_result = ((uint32_t)ACT_N << 16)
             | ((uint32_t)cnt << 8)
             | ((uint32_t)sum_end & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_activity_sel();
    for (;;);
}
