/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Sweep Line Max Interval Depth fixture.
 *
 * Find the maximum number of intervals overlapping at any single point.
 * Uses coordinate-compression sweep events.
 *
 * Distinctive decompiler idioms:
 *   1. Create events: (l, +1) for interval open, (r+1, -1) for close
 *   2. Sort events by x; ties: closes (-1) before opens (+1) for strict containment
 *   3. `cur += ev[i].d; if (cur > max_depth) max_depth = cur` — sweep sum
 *   4. Answer at each event point; no explicit interval data structure
 *   5. `ne = 2 * n_intervals` — exactly two events per interval
 *
 * Intervals: [1,5], [2,7], [4,6], [8,10]
 * Events (sorted):
 *   x=1: +1; x=2: +1; x=4: +1; x=6: -1; x=7: -1 (wait: r+1)
 *
 * Actually: close events at r+1:
 *   Open  at 1,2,4,8 (+1 each)
 *   Close at 6,8,7,11 (-1 each)
 * Sorted: 1+,2+,4+,6-,7-,8+,8-,11-
 * Running sum (sort: close before open at same x):
 *   After 1+: 1; 2+: 2; 4+: 3; 6-: 2; 7-: 1; 8+ then 8-: stays 1
 *   max = 3 (at point 4..5)
 * n_events = 8, max_depth = 3, n_intervals = 4
 *
 * n_intervals = 4  = 0x04
 * max_depth   = 3  = 0x03
 * n_events    = 8  = 0x08
 *
 * g_result = (n_intervals << 16) | (max_depth << 8) | n_events = 0x040308
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SW_NI 4
#define SW_MAX_EV (SW_NI * 2)

typedef struct { int x, d; } SwEv;
static SwEv sw_ev[SW_MAX_EV];
static int  sw_ne;

static void sw_sort(void)
{
    for (int i = 1; i < sw_ne; i++) {
        SwEv k = sw_ev[i];
        int j = i - 1;
        while (j >= 0 && (sw_ev[j].x > k.x || (sw_ev[j].x == k.x && sw_ev[j].d > k.d))) {
            sw_ev[j + 1] = sw_ev[j]; j--;
        }
        sw_ev[j + 1] = k;
    }
}

void test_sweep_interval(void)
{
    static const int ls[SW_NI] = {1, 2, 4, 8};
    static const int rs[SW_NI] = {5, 7, 6, 10};

    sw_ne = 0;
    for (int i = 0; i < SW_NI; i++) {
        sw_ev[sw_ne++] = (SwEv){ ls[i],      +1 };
        sw_ev[sw_ne++] = (SwEv){ rs[i] + 1,  -1 };
    }

    sw_sort();

    int cur = 0, mx = 0;
    for (int i = 0; i < sw_ne; i++) {
        cur += sw_ev[i].d;
        if (cur > mx) mx = cur;
    }
    /* mx=3, sw_ne=8 */

    g_result = ((uint32_t)SW_NI << 16)
             | ((uint32_t)mx    << 8)
             | ((uint32_t)sw_ne & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_sweep_interval();
    for (;;);
}
