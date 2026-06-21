/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Next Greater Element (monotonic stack) fixture.
 *
 * For each element, find the first element to its right that is larger.
 * Classic monotonic (decreasing) stack O(n) algorithm:
 *
 *   while stack not empty && arr[stack.top] < arr[i]:
 *     nge[stack.pop()] = arr[i]
 *   stack.push(i)
 *
 * Distinctive decompiler idioms:
 *   1. while (top >= 0 && arr[stack[top]] < arr[i]) pop + assign
 *   2. stack[++top] = i   ← index stack push
 *
 * Input (n=8): {4, 5, 2, 10, 8, 3, 6, 1}
 *
 * NGE trace:
 *   i=0 arr=4  → push 0
 *   i=1 arr=5  → pop 0(4<5): nge[0]=5; push 1
 *   i=2 arr=2  → push 2
 *   i=3 arr=10 → pop 2(2<10): nge[2]=10; pop 1(5<10): nge[1]=10; push 3
 *   i=4 arr=8  → push 4
 *   i=5 arr=3  → push 5
 *   i=6 arr=6  → pop 5(3<6): nge[5]=6; push 6
 *   i=7 arr=1  → push 7
 *   end: indices {3,4,6,7} remain → nge=-1
 *
 *   NGE = {5, 10, 10, -1, -1, 6, -1, -1}
 *   Non-(-1): {5, 10, 10, 6} → count=4, xor=5^10^10^6=3
 *
 *   n      = 8
 *   count  = 4
 *   xor    = 3
 *
 * g_result = (n << 16) | (count << 8) | xor = 0x00080403
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Next Greater Element ─────────────────────────────────────────────────── */

#define NGE_N 8

static int nge_result[NGE_N];
static int nge_stack[NGE_N];

static void next_greater(const int *arr, int n)
{
    int top = -1;
    for (int i = 0; i < n; i++) nge_result[i] = -1;

    for (int i = 0; i < n; i++) {
        while (top >= 0 && arr[nge_stack[top]] < arr[i])
            nge_result[nge_stack[top--]] = arr[i];
        nge_stack[++top] = i;
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_next_greater(void)
{
    static const int arr[NGE_N] = {4, 5, 2, 10, 8, 3, 6, 1};

    next_greater(arr, NGE_N);
    /* nge_result = {5,10,10,-1,-1,6,-1,-1} */

    uint32_t count = 0, xor_nge = 0;
    for (int i = 0; i < NGE_N; i++) {
        if (nge_result[i] != -1) {
            count++;
            xor_nge ^= (uint32_t)nge_result[i];
        }
    }

    g_result = ((uint32_t)NGE_N << 16)
             | (count << 8)
             | (xor_nge & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_next_greater();
    for (;;);
}
