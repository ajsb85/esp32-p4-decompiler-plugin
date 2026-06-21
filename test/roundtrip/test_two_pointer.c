/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Two-pointer pair sum fixture.
 *
 * Classic two-pointer technique on a sorted array:
 * Find all unique pairs (lo, hi) where arr[lo] + arr[hi] == target.
 *
 * Algorithm (O(n)):
 *   lo = 0; hi = n-1;
 *   while (lo < hi):
 *       s = arr[lo] + arr[hi];
 *       if (s == target): record; lo++; hi--;
 *       else if (s < target): lo++;
 *       else: hi--;
 *
 * Distinctive decompiler idioms:
 *   1. lo/hi converging pointers (not indices that cross)
 *   2. Three-way branch on sum vs target
 *   3. Simultaneous lo++; hi-- on match
 *
 * Input (n=10, sorted): {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
 * Target: 11
 *
 * Trace:
 *   lo=0 hi=9: 1+10=11 ✓ → count++, lo_val_xor^=1, lo++, hi--
 *   lo=1 hi=8: 2+9=11  ✓ → count++, lo_val_xor^=2, lo++, hi--
 *   lo=2 hi=7: 3+8=11  ✓ → count++, lo_val_xor^=3, lo++, hi--
 *   lo=3 hi=6: 4+7=11  ✓ → count++, lo_val_xor^=4, lo++, hi--
 *   lo=4 hi=5: 5+6=11  ✓ → count++, lo_val_xor^=5, lo++, hi--
 *   lo=5 > hi=4 → done
 *
 * count    = 5
 * xor_lo   = 1^2^3^4^5 = 1
 * sum_lo   = 1+2+3+4+5 = 15
 *
 * g_result = (n << 16) | (count << 8) | xor_lo = 0x000A0501
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Two-pointer pair sum ─────────────────────────────────────────────────── */

#define TP_N      10
#define TP_TARGET 11

static void two_pointer_pairs(const int *arr, int n, int target,
                               int *count_out, uint32_t *xor_lo_out)
{
    int lo = 0, hi = n - 1;
    int count = 0;
    uint32_t xor_lo = 0;
    while (lo < hi) {
        int s = arr[lo] + arr[hi];
        if (s == target) {
            count++;
            xor_lo ^= (uint32_t)arr[lo];
            lo++;
            hi--;
        } else if (s < target) {
            lo++;
        } else {
            hi--;
        }
    }
    *count_out  = count;
    *xor_lo_out = xor_lo;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_two_pointer(void)
{
    static const int arr[TP_N] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int count;
    uint32_t xor_lo;

    two_pointer_pairs(arr, TP_N, TP_TARGET, &count, &xor_lo);
    /* count=5, xor_lo=1 */

    g_result = ((uint32_t)TP_N << 16)
             | ((uint32_t)count << 8)
             | (xor_lo & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_two_pointer();
    for (;;);
}
