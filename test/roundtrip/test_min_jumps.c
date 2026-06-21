/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Minimum Jumps (BFS/greedy O(n)).
 *
 * Finds the minimum number of jumps to reach the last index.
 * Greedy: track current reachable end and farthest reachable point.
 *
 * Distinctive decompiler idioms:
 *   1. `jmp=0; cur_end=0; far=0` — greedy state initialization
 *   2. `if(i+arr[i]>far) far=i+arr[i]` — extend farthest in current wave
 *   3. `if(i==cur_end){ jmp++; cur_end=far; }` — advance wave boundary
 *
 * Arrays:
 *   {2,3,1,1,4} → min_jumps=2
 *   {2,3,0,1,4} → min_jumps=2
 *   {1,1,1,1,1,1} → min_jumps=5
 *
 * n_tests=3, sum_jumps=9, xor_jumps=2^2^5=5
 *
 * g_result = (3<<16)|(sum<<8)|xor = 0x00030905
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_min_jumps(void)
{
    static const int arrs[3][6] = {
        {2,3,1,1,4,0}, {2,3,0,1,4,0}, {1,1,1,1,1,1}
    };
    static const int ns[3] = {5, 5, 6};
    int jumps[3];

    for (int t = 0; t < 3; t++) {
        int n = ns[t], jmp = 0, cur_end = 0, far = 0;
        for (int i = 0; i < n - 1; i++) {
            if (i + arrs[t][i] > far) far = i + arrs[t][i];
            if (i == cur_end) { jmp++; cur_end = far; }
        }
        jumps[t] = jmp;
    }

    int sum = jumps[0] + jumps[1] + jumps[2];
    int xr  = jumps[0] ^ jumps[1] ^ jumps[2];
    /* sum=9, xr=5 */
    g_result = (3u << 16)
             | ((uint32_t)sum << 8)
             | (uint32_t)xr;
}

__attribute__((noreturn)) void _start(void)
{
    test_min_jumps();
    for (;;);
}
