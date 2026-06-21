/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Bitonic Subsequence (O(n²) DP) fixture.
 *
 * A bitonic subsequence first strictly increases then strictly decreases.
 * Classic two-pass DP:
 *   LIS[i] = length of longest strictly increasing subsequence ENDING at i (forward)
 *   LDS[i] = length of longest strictly decreasing subsequence STARTING at i (backward)
 *   LBS[i] = LIS[i] + LDS[i] - 1   (element at i counted once)
 *
 * Distinctive decompiler idioms:
 *   1. `for j<i: if arr[j]<arr[i] && lis[j]+1>lis[i]: lis[i]=lis[j]+1` — forward LIS
 *   2. `for j>i: if arr[j]<arr[i] && lds[j]+1>lds[i]: lds[i]=lds[j]+1` — backward LDS
 *   3. `lbs[i] = lis[i] + lds[i] - 1`  — combine
 *   4. `if lbs[i] > max_lbs: max_lbs = lbs[i]`  — global max
 *
 * Input: arr = {1, 5, 2, 8, 3}  (n = 5)
 *   LIS = {1, 2, 2, 3, 3}
 *   LDS = {1, 2, 1, 2, 1}
 *   LBS = {1, 3, 2, 4, 3}  →  max = 4
 *
 * n       = 5
 * max_lbs = 4
 * xor_lbs = 1^3^2^4^3 = 7
 *
 * g_result = (n << 16) | (max_lbs << 8) | xor_lbs = 0x00050407
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Longest Bitonic Subsequence ─────────────────────────────────────────────── */

#define LB_N 5

static const int lb_arr[LB_N] = {1, 5, 2, 8, 3};
static int lb_lis[LB_N];
static int lb_lds[LB_N];

/* ── Test entry point ────────────────────────────────────────────────────────── */

void test_longest_bitonic(void)
{
    /* forward LIS: longest increasing subseq ending at i */
    for (int i = 0; i < LB_N; i++) {
        lb_lis[i] = 1;
        for (int j = 0; j < i; j++) {
            if (lb_arr[j] < lb_arr[i] && lb_lis[j] + 1 > lb_lis[i])
                lb_lis[i] = lb_lis[j] + 1;
        }
    }

    /* backward LDS: longest decreasing subseq starting at i */
    for (int i = LB_N - 1; i >= 0; i--) {
        lb_lds[i] = 1;
        for (int j = i + 1; j < LB_N; j++) {
            if (lb_arr[j] < lb_arr[i] && lb_lds[j] + 1 > lb_lds[i])
                lb_lds[i] = lb_lds[j] + 1;
        }
    }

    /* combine: LBS[i] = LIS[i] + LDS[i] - 1 */
    int     max_lbs = 0;
    uint32_t xor_lbs = 0;
    for (int i = 0; i < LB_N; i++) {
        int lbs = lb_lis[i] + lb_lds[i] - 1;
        if (lbs > max_lbs) max_lbs = lbs;
        xor_lbs ^= (uint32_t)lbs;
    }
    /* max_lbs=4, xor_lbs=7 */
    g_result = ((uint32_t)LB_N << 16) | ((uint32_t)max_lbs << 8) | (xor_lbs & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_longest_bitonic();
    for (;;);
}
