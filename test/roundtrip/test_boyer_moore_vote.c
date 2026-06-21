/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Boyer-Moore Majority Voting fixture.
 *
 * Find the majority element (appears > n/2 times) in O(n) time O(1) space.
 *
 * Phase 1 — vote:
 *   candidate = arr[0]; count = 1;
 *   for i = 1..n-1:
 *     if count == 0: candidate = arr[i]; count = 1;
 *     else if arr[i] == candidate: count++;
 *     else: count--;
 *
 * Phase 2 — verify:
 *   count actual occurrences of candidate.
 *
 * Distinctive decompiler idioms:
 *   1. count == 0 reset branch (not present in any other algorithm)
 *   2. Three-way: ==0 reset; ==candidate count++; else count--
 *   3. Separate verification pass
 *
 * Input (n=7): {3, 2, 3, 1, 3, 3, 2}
 *
 * Voting trace:
 *   init: cand=3, cnt=1
 *   i=1: arr=2≠3, cnt=0
 *   i=2: cnt==0 → cand=3, cnt=1
 *   i=3: arr=1≠3, cnt=0
 *   i=4: cnt==0 → cand=3, cnt=1
 *   i=5: arr=3==3, cnt=2
 *   i=6: arr=2≠3, cnt=1
 *   → candidate = 3
 *
 * Verify: 3 appears 4 times in the array → majority confirmed.
 *
 * n        = 7
 * candidate= 3
 * freq     = 4
 *
 * g_result = (n << 16) | (candidate << 8) | freq = 0x00070304
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Boyer-Moore Majority Vote ────────────────────────────────────────────── */

#define BMV_N 7

static void boyer_moore_vote(const int *arr, int n, int *cand_out, int *freq_out)
{
    /* Phase 1: find candidate */
    int candidate = arr[0], count = 1;
    for (int i = 1; i < n; i++) {
        if (count == 0) {
            candidate = arr[i];
            count = 1;
        } else if (arr[i] == candidate) {
            count++;
        } else {
            count--;
        }
    }
    /* Phase 2: verify */
    int freq = 0;
    for (int i = 0; i < n; i++)
        if (arr[i] == candidate) freq++;
    *cand_out = candidate;
    *freq_out = freq;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_boyer_moore_vote(void)
{
    static const int arr[BMV_N] = {3, 2, 3, 1, 3, 3, 2};
    int candidate, freq;

    boyer_moore_vote(arr, BMV_N, &candidate, &freq);
    /* candidate=3, freq=4 */

    g_result = ((uint32_t)BMV_N << 16)
             | ((uint32_t)candidate << 8)
             | (uint32_t)freq;
}

__attribute__((noreturn)) void _start(void)
{
    test_boyer_moore_vote();
    for (;;);
}
