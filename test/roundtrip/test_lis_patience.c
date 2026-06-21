/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — O(n log n) LIS via Patience Sorting fixture.
 *
 * Maintains a "tails" array where tails[i] = smallest tail element of all
 * increasing subsequences of length i+1 seen so far. Binary search locates
 * where the current element fits; replacing it keeps tails non-decreasing.
 *
 * Distinctive decompiler idioms:
 *   1. `pos = lower_bound(tails, tails+len, a[i])` — find insertion point
 *   2. `tails[pos] = a[i]` — replace/extend the tails array
 *   3. `if (pos == len) len++` — extend length only when new tail is added at end
 *   4. Binary search loop: `while (lo < hi) { mid=(lo+hi)/2; if(tails[mid]<v) lo=mid+1; else hi=mid; }`
 *   5. Final `len` = LIS length; tails[0] always equals minimum seen element
 *
 * Array: [3,1,4,1,5,9,2,6,5,3,5] (n=11)
 * Patience sort trace:
 *   →[3]; 1→[1]; 4→[1,4]; 1→[1,4]; 5→[1,4,5]; 9→[1,4,5,9];
 *   2→[1,2,5,9]; 6→[1,2,5,6]; 5→[1,2,5,6]; 3→[1,2,3,6]; 5→[1,2,3,5]
 * LIS length = 4 (e.g., 1,2,3,5 at positions 1,6,9,10)
 *
 * n           = 11 = 0x0B
 * lis_len     = 4  = 0x04
 * tails[0]    = 1  = 0x01  (smallest element in any length-1 IS)
 *
 * g_result = (n << 16) | (lis_len << 8) | tails[0] = 0x0B0401
 */
#include <stdint.h>

volatile uint32_t g_result;

#define LA_N 11

static const int la_a[LA_N] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5};
static int la_tails[LA_N];

static int la_lb(int *a, int n, int v)
{
    int lo = 0, hi = n;
    while (lo < hi) { int m = (lo + hi) / 2; if (a[m] < v) lo = m + 1; else hi = m; }
    return lo;
}

void test_lis_patience(void)
{
    int len = 0;
    for (int i = 0; i < LA_N; i++) {
        int pos = la_lb(la_tails, len, la_a[i]);
        la_tails[pos] = la_a[i];
        if (pos == len) len++;
    }
    /* len=4, la_tails[0]=1 */

    g_result = ((uint32_t)LA_N      << 16)
             | ((uint32_t)len       << 8)
             | ((uint32_t)la_tails[0] & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_lis_patience();
    for (;;);
}
