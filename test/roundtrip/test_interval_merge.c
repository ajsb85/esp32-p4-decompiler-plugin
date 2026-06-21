/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Merge overlapping intervals fixture.
 *
 * Given intervals sorted by start time, merge all overlapping intervals
 * by extending the current endpoint when the next start ≤ current end.
 *
 * Distinctive decompiler idioms:
 *   1. `if (starts[i] <= cur_end) { cur_end = max(cur_end, ends[i]) }` — extend
 *   2. `else { emit(cur_start, cur_end); cur_start = ...; }` — start new interval
 *   3. Emit final interval after loop (off-by-one pattern)
 *
 * Input:  {[1,3], [2,6], [8,10], [15,18]}
 * Output: {[1,6], [8,10], [15,18]}  — 3 merged intervals
 *
 * n_input    = 4
 * n_merged   = 3
 * xor_ends   = 6 ^ 10 ^ 18 = 30  (0x1E)
 *
 * g_result = (n_input << 16) | (n_merged << 8) | xor_ends = 0x0004031E
 */
#include <stdint.h>

volatile uint32_t g_result;

#define IM_N 4

static const int im_starts[IM_N] = {1, 2,  8, 15};
static const int im_ends[IM_N]   = {3, 6, 10, 18};
static int im_ms[IM_N], im_me[IM_N];

void test_interval_merge(void)
{
    int n_merged = 0;
    int cur_s = im_starts[0], cur_e = im_ends[0];

    for (int i = 1; i < IM_N; i++) {
        if (im_starts[i] <= cur_e) {
            if (im_ends[i] > cur_e) cur_e = im_ends[i];
        } else {
            im_ms[n_merged] = cur_s;
            im_me[n_merged] = cur_e;
            n_merged++;
            cur_s = im_starts[i];
            cur_e = im_ends[i];
        }
    }
    im_ms[n_merged] = cur_s;
    im_me[n_merged] = cur_e;
    n_merged++;

    uint32_t xor_ends = 0;
    for (int i = 0; i < n_merged; i++)
        xor_ends ^= (uint32_t)im_me[i];

    g_result = ((uint32_t)IM_N << 16) | ((uint32_t)n_merged << 8) | (xor_ends & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_interval_merge();
    for (;;);
}
