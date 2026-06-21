/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Jump Game (Greedy Reach) fixture.
 *
 * Given an array where arr[i] is the maximum jump distance from position i,
 * determine whether the last position is reachable from position 0.
 *
 * Greedy idiom: maintain max_reach; advance i only while i ≤ max_reach.
 *
 * Distinctive decompiler idioms:
 *   1. `if (i > max_reach) return 0` — early-exit pruning (no DFS/BFS needed)
 *   2. `if (i + arr[i] > max_reach) max_reach = i + arr[i]` — greedy update
 *   3. Single forward pass with no auxiliary data structure
 *
 * Five test cases:
 *   1. {2,3,1,1,4}  n=5 → reachable    (1)
 *   2. {3,2,1,0,4}  n=5 → not          (0)
 *   3. {1,2,3,4,0}  n=5 → reachable    (1)
 *   4. {0,0,1,1,1}  n=5 → not          (0)
 *   5. {5,4,3,2,1,0} n=6 → reachable   (1)
 *
 * n_tests      = 5
 * count_reach  = 3
 * xor_results  = 1^0^1^0^1 = 1
 *
 * g_result = (n_tests << 16) | (count_reach << 8) | xor_results = 0x00050301
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Jump Game ────────────────────────────────────────────────────────────── */

#define JG_TESTS 5

static int jump_game(const int *arr, int n)
{
    int max_reach = 0;
    for (int i = 0; i < n; i++) {
        if (i > max_reach) return 0;
        if (i + arr[i] > max_reach) max_reach = i + arr[i];
    }
    return 1;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_jump_game(void)
{
    static const int a0[] = {2, 3, 1, 1, 4};   /* reachable */
    static const int a1[] = {3, 2, 1, 0, 4};   /* not reachable */
    static const int a2[] = {1, 2, 3, 4, 0};   /* reachable */
    static const int a3[] = {0, 0, 1, 1, 1};   /* not reachable */
    static const int a4[] = {5, 4, 3, 2, 1, 0};/* reachable */

    static const int *arrs[] = {a0, a1, a2, a3, a4};
    static const int  lens[] = { 5,  5,  5,  5,  6};

    uint32_t count_reach = 0, xor_res = 0;
    for (int t = 0; t < JG_TESTS; t++) {
        int r = jump_game(arrs[t], lens[t]);
        if (r) count_reach++;
        xor_res ^= (uint32_t)r;
    }
    /* count=3, xor=1 */

    g_result = ((uint32_t)JG_TESTS << 16) | (count_reach << 8) | (xor_res & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_jump_game();
    for (;;);
}
