/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Floyd's Cycle Detection (tortoise and hare) fixture.
 *
 * Given a sequence defined by a next[] array, find:
 *   1. Whether a cycle exists  (phase 1: slow/fast pointer meet)
 *   2. The cycle entry node    (phase 2: reset slow to start, advance both by 1)
 *   3. The cycle length        (phase 3: count until fast returns to meeting point)
 *
 * Distinctive idioms:
 *   Phase 1: do { slow=f(slow); fast=f(f(fast)); } while (slow != fast);
 *   Phase 2: slow=0; while(slow!=fast){slow=f(slow); fast=f(fast);}  (entry node)
 *   Phase 3: len=1; fast=f(slow); while(fast!=slow){fast=f(fast);len++;} (length)
 *
 * Input: n=7 nodes, next[]={1,2,3,4,2,6,2}
 *   Path: 0→1→2→3→4→2 (cycle: 2→3→4→2, length=3)
 *
 * Floyd trace:
 *   Phase 1 (detect):
 *     step 1: slow=1, fast=2
 *     step 2: slow=2, fast=4
 *     step 3: slow=3, fast=3  ← meet at 3
 *
 *   Phase 2 (start):
 *     slow=0, fast=3
 *     step 1: slow=1, fast=4
 *     step 2: slow=2, fast=2  ← cycle_start=2
 *
 *   Phase 3 (length):
 *     fast=next[2]=3, len=1
 *     fast=next[3]=4, len=2
 *     fast=next[4]=2=slow     ← cycle_len=3
 *
 * n_nodes     = 7
 * cycle_start = 2
 * cycle_len   = 3
 *
 * g_result = (n_nodes << 16) | (cycle_start << 8) | cycle_len = 0x00070203
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Floyd's Cycle Detection ──────────────────────────────────────────────── */

#define FC_N 7

static const int fc_next[FC_N] = {1, 2, 3, 4, 2, 6, 2};

static void floyd_cycle(int *start_out, int *len_out)
{
    /* Phase 1: detect meeting point */
    int slow = 0, fast = 0;
    do {
        slow = fc_next[slow];
        fast = fc_next[fc_next[fast]];
    } while (slow != fast);

    /* Phase 2: find cycle entry node */
    slow = 0;
    while (slow != fast) {
        slow = fc_next[slow];
        fast = fc_next[fast];
    }
    *start_out = slow;

    /* Phase 3: find cycle length */
    int len = 1;
    fast = fc_next[slow];
    while (fast != slow) {
        fast = fc_next[fast];
        len++;
    }
    *len_out = len;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_floyd_cycle(void)
{
    int cycle_start, cycle_len;
    floyd_cycle(&cycle_start, &cycle_len);
    /* cycle_start=2, cycle_len=3 */

    g_result = ((uint32_t)FC_N << 16)
             | ((uint32_t)cycle_start << 8)
             | (uint32_t)cycle_len;
}

__attribute__((noreturn)) void _start(void)
{
    test_floyd_cycle();
    for (;;);
}
