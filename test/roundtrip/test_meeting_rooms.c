/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Meeting Rooms (attend-all check, 3 sets).
 *
 * Determines if a person can attend all meetings in a schedule.
 * Algorithm: sort intervals by start time, check if any consecutive pair overlaps.
 *
 * Distinctive decompiler idioms:
 *   1. Insertion sort by start time: `while(j>=0&&ss[j]>ks)` — sort 3 intervals
 *   2. `if(ss[i]<se[i-1]) can_attend=0` — overlap detection after sort
 *   3. Sum end times of "attendable" sets for the low byte
 *
 * Sets:
 *   Set 0: (0,30),(5,10),(15,20) → overlap → can't attend (ends=30+10+20=60)
 *   Set 1: (7,10),(2,4),(6,8)    → overlap → can't attend (ends=10+4+8=22)
 *   Set 2: (1,5),(6,10),(11,15)  → no overlap → can attend (ends=5+10+15=30)
 *
 * n_sets=3, can_attend=1, sum_end_of_attendable=5+10+15=30
 *
 * g_result = (3<<16)|(can_attend<<8)|(sum_end&0xFF) = 0x0003011E
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_meeting_rooms(void)
{
    static const int sta[3][3] = {{0,5,15}, {7,2,6},  {1,6,11}};
    static const int end_t[3][3] = {{30,10,20}, {10,4,8}, {5,10,15}};
    int can_attend[3] = {1, 1, 1};
    int i, s;

    for (s = 0; s < 3; s++) {
        int ss[3] = {sta[s][0], sta[s][1], sta[s][2]};
        int se[3] = {end_t[s][0], end_t[s][1], end_t[s][2]};
        /* Insertion sort by start */
        for (i = 1; i < 3; i++) {
            int ks = ss[i], ke = se[i], j = i - 1;
            while (j >= 0 && ss[j] > ks) {
                ss[j+1] = ss[j]; se[j+1] = se[j]; j--;
            }
            ss[j+1] = ks; se[j+1] = ke;
        }
        /* Check overlap */
        for (i = 1; i < 3; i++)
            if (ss[i] < se[i-1]) can_attend[s] = 0;
    }

    int cnt = 0;
    uint32_t sum_end = 0;
    for (s = 0; s < 3; s++) {
        if (can_attend[s]) {
            cnt++;
            for (i = 0; i < 3; i++) sum_end += (uint32_t)end_t[s][i];
        }
    }
    /* cnt=1, sum_end=30=0x1E */
    g_result = (3u << 16)
             | ((uint32_t)cnt << 8)
             | (sum_end & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_meeting_rooms();
    for (;;);
}
