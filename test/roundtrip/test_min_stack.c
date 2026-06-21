/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Minimum Stack fixture.
 *
 * A stack that supports O(1) getMin() using an auxiliary min-tracking stack.
 *
 * push(x):  main[top++] = x;
 *           min_stk[top] = (x < min_stk[top-1]) ? x : min_stk[top-1];
 * pop():    --top;
 * getMin(): return min_stk[top];
 *
 * Distinctive decompiler idioms:
 *   1. Dual-array push: main[top]=x; min_stk[top]=min(x, prev_min)
 *   2. Single decrement for both stacks: --top
 *   3. Read from min_stk[top] (not main[top]) for getMin
 *
 * Operations:
 *   push(5): main=[5],       min=[5]
 *   push(3): main=[5,3],     min=[5,3]
 *   push(7): main=[5,3,7],   min=[5,3,3]
 *   push(2): main=[5,3,7,2], min=[5,3,3,2]
 *   getMin() → 2
 *   pop()    → main=[5,3,7], min=[5,3,3]
 *   getMin() → 3
 *   pop()    → main=[5,3],   min=[5,3]
 *   getMin() → 3
 *   pop()    → main=[5],     min=[5]
 *   getMin() → 5
 *
 * n_pushes = 4
 * min queries: {2, 3, 3, 5}
 * sum_mins = 2+3+3+5 = 13  (0x0D)
 * xor_mins = 2^3^3^5 = 7   (0x07)
 *
 * g_result = (n_pushes << 16) | (sum_mins << 8) | xor_mins = 0x00040D07
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Minimum Stack ────────────────────────────────────────────────────────── */

#define MS_CAP 8

static int ms_main[MS_CAP];
static int ms_min[MS_CAP];
static int ms_top;

static void ms_init(void)
{
    ms_top = 1;
    ms_min[0] = 0x7fffffff;   /* sentinel: index 0 is never the top */
}

static void ms_push(int x)
{
    ms_main[ms_top - 1] = x;
    ms_min[ms_top]  = (x < ms_min[ms_top - 1]) ? x : ms_min[ms_top - 1];
    ms_top++;
}

static void ms_pop(void) { ms_top--; }

static int ms_get_min(void) { return ms_min[ms_top - 1]; }

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_min_stack(void)
{
    ms_init();

    ms_push(5);
    ms_push(3);
    ms_push(7);
    ms_push(2);

    uint32_t sum_m = 0, xor_m = 0;

    sum_m += (uint32_t)ms_get_min(); xor_m ^= (uint32_t)ms_get_min(); /* 2 */
    ms_pop();
    sum_m += (uint32_t)ms_get_min(); xor_m ^= (uint32_t)ms_get_min(); /* 3 */
    ms_pop();
    sum_m += (uint32_t)ms_get_min(); xor_m ^= (uint32_t)ms_get_min(); /* 3 */
    ms_pop();
    sum_m += (uint32_t)ms_get_min(); xor_m ^= (uint32_t)ms_get_min(); /* 5 */
    /* sum=13, xor=7 */

    g_result = (4u << 16) | (sum_m << 8) | (xor_m & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_min_stack();
    for (;;);
}
