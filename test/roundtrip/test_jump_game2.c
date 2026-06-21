/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Jump Game II (minimum jumps) fixture.
 *
 * Finds the minimum number of jumps to reach the last index using a greedy
 * algorithm that tracks the current range boundary and farthest reachable.
 *
 * Distinctive decompiler idioms:
 *   1. `far = max(far, i + arr[i])` — extend farthest reachable
 *   2. `if(i == cur_end){ jumps++; cur_end = far }` — advance to next range
 *   3. `if(cur_end >= n-1) break` — early exit when target reachable
 *
 * Test cases:
 *   1. {2,3,1,1,4} → 2 jumps (0→1→last)
 *   2. {2,3,0,1,4} → 2 jumps (0→1→last)
 *   3. {1,2,3,4,5} → 3 jumps (0→1→3→last)
 *
 * n_tests=3, sum_jumps=7, xor_jumps=2^2^3=3
 * g_result = (3 << 16) | (7 << 8) | 3 = 0x00030703
 */
#include <stdint.h>

volatile uint32_t g_result;

static int jg2_min_jumps(const int *arr, int n)
{
    int jumps = 0, cur_end = 0, far = 0;
    for (int i = 0; i < n - 1; i++) {
        if (i + arr[i] > far) far = i + arr[i];
        if (i == cur_end) {
            jumps++;
            cur_end = far;
            if (cur_end >= n - 1) break;
        }
    }
    return jumps;
}

void test_jump_game2(void)
{
    const int a1[5] = {2, 3, 1, 1, 4};
    const int a2[5] = {2, 3, 0, 1, 4};
    const int a3[5] = {1, 2, 3, 4, 5};

    int j1 = jg2_min_jumps(a1, 5);
    int j2 = jg2_min_jumps(a2, 5);
    int j3 = jg2_min_jumps(a3, 5);

    uint32_t sum = (uint32_t)(j1 + j2 + j3);     /* 7 */
    uint32_t xr  = (uint32_t)(j1 ^ j2 ^ j3);      /* 3 */

    g_result = (3u << 16) | ((sum & 0xFFu) << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_jump_game2();
    for (;;);
}
