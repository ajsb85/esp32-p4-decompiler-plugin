/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Spiral Matrix Traversal fixture.
 *
 * Traverses a matrix in spiral order (clockwise from top-left) using
 * boundary shrinking: top/bottom/left/right pointers collapse inward.
 *
 * Distinctive decompiler idioms:
 *   1. `for(c=left;c<=right;c++) out[idx++]=mat[top][c]; top++` — top row
 *   2. `for(r=top;r<=bot;r++) out[idx++]=mat[r][right]; right--` — right col
 *   3. `if(top<=bot)` guard before bottom-row and left-col passes
 *
 * Matrix 3×4:
 *   1  2  3  4
 *   5  6  7  8
 *   9 10 11 12
 * Spiral: 1,2,3,4,8,12,11,10,9,5,6,7
 * n=12, sum=78=0x4E, xor=12=0x0C
 *
 * g_result = (n<<16)|(sum&0xFF)<<8|(xor&0xFF) = 0x000C4E0C
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_spiral_matrix(void)
{
    static const int mat[3][4] = {
        { 1,  2,  3,  4},
        { 5,  6,  7,  8},
        { 9, 10, 11, 12}
    };
    int spiral[12], idx = 0;
    int top = 0, bot = 2, left_b = 0, right_b = 3;

    while (top <= bot && left_b <= right_b) {
        /* top row → */
        for (int c = left_b; c <= right_b; c++) spiral[idx++] = mat[top][c];
        top++;
        /* right col ↓ */
        for (int r = top; r <= bot; r++) spiral[idx++] = mat[r][right_b];
        right_b--;
        /* bottom row ← */
        if (top <= bot) {
            for (int c = right_b; c >= left_b; c--) spiral[idx++] = mat[bot][c];
            bot--;
        }
        /* left col ↑ */
        if (left_b <= right_b) {
            for (int r = bot; r >= top; r--) spiral[idx++] = mat[r][left_b];
            left_b++;
        }
    }

    uint32_t sum = 0, xr = 0;
    for (int i = 0; i < idx; i++) {
        sum += (uint32_t)spiral[i];
        xr  ^= (uint32_t)spiral[i];
    }
    /* idx=12=0x0C, sum=78=0x4E, xr=12=0x0C */
    g_result = ((uint32_t)idx << 16)
             | ((sum & 0xFFu) << 8)
             | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_spiral_matrix();
    for (;;);
}
