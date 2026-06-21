/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Jump Game Greedy (can-reach-end).
 *
 * Determines if you can reach the last index from the first.
 * Greedy: track the maximum index reachable; if current > max, stuck.
 *
 * Distinctive decompiler idioms:
 *   1. `for(i<n-1) if(i>mx){can=0;break}` — stuck check
 *   2. `if(i+arr[i]>mx) mx=i+arr[i]` — extend reachable horizon
 *   3. `can=1` after full pass means all positions are reachable
 *
 * Arrays:
 *   {2,3,1,1,4} → can=1 (always reach end)
 *   {3,2,1,0,4} → can=0 (stuck at index 3)
 *   {1,2,3,4,5} → can=1
 *
 * n_tests=3, can_count=2, encode=can[0]*4+can[1]*2+can[2]=5
 *
 * g_result = (3<<16)|(can_count<<8)|encode = 0x00030205
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_jump_game_greedy(void)
{
    static const int arrs[3][5] = {
        {2,3,1,1,4}, {3,2,1,0,4}, {1,2,3,4,5}
    };
    int ns[3] = {5, 5, 5};
    int can[3];

    for (int t = 0; t < 3; t++) {
        int n = ns[t], mx = 0, ok = 1;
        for (int i = 0; i < n - 1; i++) {
            if (i > mx) { ok = 0; break; }
            if (i + arrs[t][i] > mx) mx = i + arrs[t][i];
        }
        can[t] = ok;
    }

    int cnt = can[0] + can[1] + can[2];
    int enc = can[0] * 4 + can[1] * 2 + can[2];
    /* cnt=2, enc=4+0+1=5 */
    g_result = (3u << 16)
             | ((uint32_t)cnt << 8)
             | (uint32_t)enc;
}

__attribute__((noreturn)) void _start(void)
{
    test_jump_game_greedy();
    for (;;);
}
