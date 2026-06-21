/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Rotate Image 90° Clockwise (in-place).
 *
 * Rotates an N×N matrix 90° clockwise using: transpose then reverse each row.
 * Two-phase: transpose swaps (i,j)↔(j,i); row-reverse flips L↔R.
 *
 * Distinctive decompiler idioms:
 *   1. `for(i<n) for(j=i+1;j<n) swap(m[i][j],m[j][i])` — in-place transpose
 *   2. `for(i<n) lo=0,hi=n-1; while(lo<hi) swap(m[i][lo++],m[i][hi--])` — row flip
 *   3. `g_result=(n<<16)|(sum_diag<<8)|m[0][0]` — post-rotation diag sum
 *
 * Matrix 3×3:
 *   1 2 3       7 4 1
 *   4 5 6  →   8 5 2
 *   7 8 9       9 6 3
 *
 * Main diagonal after rotation: 7+5+3=15, top-left=7
 * g_result = (3<<16)|(15<<8)|7 = 0x00030F07
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_rotate_image(void)
{
    int m[3][3] = {{1,2,3},{4,5,6},{7,8,9}};
    int n = 3, i, j;

    /* Transpose */
    for (i = 0; i < n; i++)
        for (j = i + 1; j < n; j++) {
            int t = m[i][j]; m[i][j] = m[j][i]; m[j][i] = t;
        }
    /* Reverse each row */
    for (i = 0; i < n; i++) {
        int lo = 0, hi = n - 1;
        while (lo < hi) {
            int t = m[i][lo]; m[i][lo] = m[i][hi]; m[i][hi] = t;
            lo++; hi--;
        }
    }
    /* After rotation: diag = m[0][0]+m[1][1]+m[2][2] = 7+5+3 = 15 */
    uint32_t diag = 0;
    for (i = 0; i < n; i++) diag += (uint32_t)m[i][i];

    g_result = ((uint32_t)n << 16)
             | ((diag & 0xFFu) << 8)
             | (uint32_t)m[0][0];
}

__attribute__((noreturn)) void _start(void)
{
    test_rotate_image();
    for (;;);
}
