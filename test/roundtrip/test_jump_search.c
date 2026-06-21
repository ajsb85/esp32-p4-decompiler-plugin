/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Jump Search O(√n) fixture.
 *
 * For a sorted array, jump forward by block_size=floor(√n),
 * then do linear backward search when we overshoot:
 *
 *   step = sqrt(n);  prev = 0;
 *   while (arr[min(step,n)-1] < key): prev=step; step+=sqrt(n)
 *   while (arr[prev] < key && prev < min(step,n)): prev++
 *   return arr[prev]==key ? prev : -1;
 *
 * Distinctive decompiler idioms vs binary search:
 *   1. Fixed-step forward scan: step += sqrt_n (not bisection)
 *   2. Backward linear pass after overshoot
 *   3. No explicit lo/hi; prev tracks last safe block start
 *
 * Integer sqrt without math.h: while((s+1)*(s+1)<=n) s++;
 *
 * Input (n=10, sorted): {1,3,5,7,9,11,13,15,17,19}
 * block_size = floor(√10) = 3
 *
 * Queries: {7, 13, 19}   (all present)
 *   find 7:  jump step=3(arr[2]=5<7),prev=3,step=6(arr[5]=11≥7) → lin prev=3..4: arr[3]=7 ✓ idx=3
 *   find 13: jump step=3(5<13),prev=3,step=6(11<13),prev=6,step=9(17≥13) → lin prev=6: arr[6]=13 ✓ idx=6
 *   find 19: jump to step=9(17<19),prev=9,step=12>10 → arr[9]=19 → lin: arr[9]=19 ✓ idx=9
 *
 * count       = 3    (all found)
 * xor_indices = 3^6^9 = 12  (0x0C)
 *
 * g_result = (n << 16) | (count << 8) | xor_indices = 0x000A030C
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Jump Search ──────────────────────────────────────────────────────────── */

#define JS_N 10

static int isqrt_js(int n)
{
    int s = 1;
    while ((s + 1) * (s + 1) <= n) s++;
    return s;
}

static int jump_search(const int *arr, int n, int key)
{
    int block = isqrt_js(n);
    int prev = 0, step = block;

    while (step < n && arr[step - 1] < key) {
        prev = step;
        step += block;
    }
    /* linear scan from prev to min(step,n) */
    int limit = (step < n) ? step : n;
    for (; prev < limit; prev++) {
        if (arr[prev] == key) return prev;
        if (arr[prev] > key)  break;
    }
    return -1;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_jump_search(void)
{
    static const int arr[JS_N] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19};
    static const int queries[]  = {7, 13, 19};

    uint32_t count = 0, xor_idx = 0;
    for (int q = 0; q < 3; q++) {
        int idx = jump_search(arr, JS_N, queries[q]);
        if (idx >= 0) {
            count++;
            xor_idx ^= (uint32_t)idx;
        }
    }
    /* count=3, xor_idx=3^6^9=12 */

    g_result = ((uint32_t)JS_N << 16) | (count << 8) | (xor_idx & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_jump_search();
    for (;;);
}
