/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Flood Fill (BFS 4-connectivity).
 *
 * Replaces a connected region of same-colored cells with a new color.
 * Uses BFS from the source pixel: queue up all adjacent same-color cells.
 *
 * Distinctive decompiler idioms:
 *   1. `if(old==nw) return` — early exit if same color
 *   2. `q[back][0]=r; q[back++][1]=c; vis[r][c]=new` — BFS enqueue
 *   3. `for(d<4) nr=r+dr[d]; if(in_bounds&&cell==old) enqueue` — 4-neighbor scan
 *
 * 4×4 grid, start=(1,1), old_color=1, new_color=2
 * Connected region: 5 cells change; grid[0][0]=2
 *
 * g_result = (rows<<16)|(changed<<8)|grid[0][0] = 0x00040502
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_flood_fill(void)
{
    int g[4][4] = {{1,1,1,0},{1,1,0,0},{0,0,1,1},{0,0,1,1}};
    int q[16][2], front = 0, back = 0, changed = 0;
    int sr = 1, sc = 1, old = g[sr][sc], nw = 2;
    static const int dr[4] = {-1,1,0,0};
    static const int dc[4] = {0,0,-1,1};

    if (old == nw) { g_result = 0; return; }

    q[back][0] = sr; q[back++][1] = sc;
    g[sr][sc] = nw;

    while (front < back) {
        int r = q[front][0], c = q[front++][1];
        changed++;
        for (int d = 0; d < 4; d++) {
            int nr = r + dr[d], nc = c + dc[d];
            if (nr >= 0 && nr < 4 && nc >= 0 && nc < 4 && g[nr][nc] == old) {
                g[nr][nc] = nw;
                q[back][0] = nr; q[back++][1] = nc;
            }
        }
    }
    /* changed=5, g[0][0]=2=new_color */
    g_result = (4u << 16)
             | ((uint32_t)changed << 8)
             | (uint32_t)g[0][0];
}

__attribute__((noreturn)) void _start(void)
{
    test_flood_fill();
    for (;;);
}
