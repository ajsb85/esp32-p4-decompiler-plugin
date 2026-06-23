/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Booth's Algorithm (Lexicographically Smallest Rotation).
 *
 * Booth's algorithm finds the starting index of the lexicographically smallest
 * rotation of a string/sequence in O(n) time.  It uses a failure-function
 * similar to KMP, operating on the double-length concatenation s+s but without
 * explicitly allocating the doubled array.
 *
 * Distinctive decompiler idioms:
 *   1. `i = f[j-1-k]` — failure-function access with offset k (not 0)
 *   2. `while (i != -1 && s[j%n] != s[(k+i+1)%n])` — modular index comparison
 *   3. `if (s[j%n] < s[(k+i+1)%n]) k = j-i-1` — shift k on strict improvement
 *   4. `f[j-k] = i+1` — failure table indexed relative to k
 *   5. `return k` — the optimal rotation start (minimizes s[k..n-1] ++ s[0..k-1])
 *
 * Input: sequence {5, 2, 3, 1, 4}  (n=5)
 * All rotations:
 *   i=0: {5,2,3,1,4}
 *   i=1: {2,3,1,4,5}
 *   i=2: {3,1,4,5,2}
 *   i=3: {1,4,5,2,3}  ← lexicographically smallest (starts with 1)
 *   i=4: {4,5,2,3,1}
 *
 * n          = 5  = 0x05
 * min_rot    = 3  = 0x03  (index of smallest rotation)
 * second_elem = 4 = 0x04  (arr[(3+1)%5] = arr[4] = 4)
 *
 * g_result = (n << 16) | (min_rot << 8) | second_elem = 0x050304 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BR_N 5
static const int br_arr[BR_N] = {5, 2, 3, 1, 4};

static int br_f[2 * BR_N]; /* failure function buffer */

static int booth_rotation(const int *s, int n)
{
    for (int i = 0; i < 2 * n; i++) br_f[i] = -1;
    int k = 0;
    for (int j = 1; j < 2 * n; j++) {
        int i = br_f[j - 1 - k];
        while (i != -1 && s[j % n] != s[(k + i + 1) % n]) {
            if (s[j % n] < s[(k + i + 1) % n])
                k = j - i - 1;
            i = br_f[i];
        }
        if (s[j % n] != s[(k + i + 1) % n]) {
            if (s[j % n] < s[k % n]) k = j;
            br_f[j - k] = -1;
        } else {
            br_f[j - k] = i + 1;
        }
    }
    return k;
}

void test_booth_rotation(void)
{
    int r = booth_rotation(br_arr, BR_N);
    /* r = 3: smallest rotation starts at index 3 → {1,4,5,2,3} */
    int second = br_arr[(r + 1) % BR_N]; /* = br_arr[4] = 4 */

    g_result = ((uint32_t)BR_N   << 16)
             | ((uint32_t)r      <<  8)
             | ((uint32_t)second & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_booth_rotation();
    for (;;);
}
