/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Activity Selection (greedy interval scheduling) fixture.
 *
 * Selects the maximum number of non-overlapping activities from a list sorted by
 * end time. Greedy: always pick the activity with the earliest end time that
 * starts after the current last selected activity ends.
 *
 * Distinctive decompiler idioms:
 *   1. `sort by end time` — or use pre-sorted input
 *   2. `if(start[i] >= last_end){ count++; last_end = end[i] }` — greedy select
 *   3. `xor of selected end times` — accumulate result
 *
 * Activities (pre-sorted by end time):
 *   (1,4),(3,5),(0,6),(5,7),(3,9),(5,9),(6,10),(8,11),(8,12),(2,14),(12,16)
 *
 * Selected: (1,4),(5,7),(8,11),(12,16) → 4 activities
 *   xor of end times = 4^7^11^16 = 24 = 0x18
 *
 * n=11, selected=4, xor_ends=24
 * g_result = (11 << 16) | (4 << 8) | 24 = 0x000B0418
 */
#include <stdint.h>

volatile uint32_t g_result;

#define AS_N 11

static const int as_start[AS_N] = {1, 3,  0, 5, 3,  5,  6,  8,  8,  2, 12};
static const int as_end[AS_N]   = {4, 5,  6, 7, 9,  9, 10, 11, 12, 14, 16};

void test_activity_selection(void)
{
    int count    = 0;
    int last_end = -1;
    uint32_t xor_ends = 0;

    for (int i = 0; i < AS_N; i++) {
        if (as_start[i] >= last_end) {
            count++;
            last_end  = as_end[i];
            xor_ends ^= (uint32_t)as_end[i];
        }
    }

    g_result = ((uint32_t)AS_N << 16)
             | ((uint32_t)(count & 0xFF) << 8)
             | (xor_ends & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_activity_selection();
    for (;;);
}
