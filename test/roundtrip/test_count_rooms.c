/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Count Rooms / Connected Components (DFS grid).
 *
 * Counts connected components of 1s in a binary grid using recursive DFS.
 * 4-connectivity: up, down, left, right.
 * Uses a generation counter instead of clearing cr_vis between runs.
 *
 * Distinctive decompiler idioms:
 *   1. `if(r<0||r>=R||c<0||c>=C||!grid[r][c]||vis==gen) return` — bounds+visited
 *   2. `vis[r][c]=gen; dfs(r-1...) dfs(r+1...) dfs(r,c-1) dfs(r,c+1)` — flood fill
 *   3. `gen++; for(r,c) if(grid&&vis!=gen){ dfs; cnt++ }` — component loop
 *
 * Grids:
 *   4×4: 3 rooms — {(0,0),(0,1),(1,0)} + {(0,3),(1,3),(2,2),(2,3)} + {(3,0)}
 *   3×5: 8 rooms — checkerboard (isolated 1s)
 *   2×3: 1 room  — all 1s
 *
 * g_result = (3<<16) | ((3+8+1)<<8) | (3^8^1) = 0x00030C0A
 */
#include <stdint.h>

volatile uint32_t g_result;

static int cr_grid[5][5];
static int cr_vis[5][5];  /* 0-initialized; compared against cr_gen */
static int cr_R, cr_C, cr_gen;

static void cr_dfs(int r, int c)
{
    if (r < 0 || r >= cr_R || c < 0 || c >= cr_C) return;
    if (!cr_grid[r][c] || cr_vis[r][c] == cr_gen) return;
    cr_vis[r][c] = cr_gen;
    cr_dfs(r-1, c); cr_dfs(r+1, c);
    cr_dfs(r, c-1); cr_dfs(r, c+1);
}

static int count_rooms(void)
{
    int cnt = 0;
    cr_gen++;  /* new generation avoids zero-fill of visited array */
    for (int r = 0; r < cr_R; r++)
        for (int c = 0; c < cr_C; c++)
            if (cr_grid[r][c] && cr_vis[r][c] != cr_gen) { cr_dfs(r, c); cnt++; }
    return cnt;
}

void test_count_rooms(void)
{
    int i, r;
    /* Grid 1: 4×4, 3 rooms */
    static const int g1[4][4] = {
        {1,1,0,1}, {1,0,0,1}, {0,0,1,1}, {1,0,0,0}
    };
    cr_R = 4; cr_C = 4;
    for (r = 0; r < 4; r++) for (i = 0; i < 4; i++) cr_grid[r][i] = g1[r][i];
    int rooms1 = count_rooms();

    /* Grid 2: 3×5 checkerboard, 8 isolated rooms */
    static const int g2[3][5] = {
        {1,0,1,0,1}, {0,1,0,1,0}, {1,0,1,0,1}
    };
    cr_R = 3; cr_C = 5;
    for (r = 0; r < 3; r++) for (i = 0; i < 5; i++) cr_grid[r][i] = g2[r][i];
    int rooms2 = count_rooms();

    /* Grid 3: 2×3 all-1s, 1 room */
    static const int g3[2][3] = {{1,1,1}, {1,1,1}};
    cr_R = 2; cr_C = 3;
    for (r = 0; r < 2; r++) for (i = 0; i < 3; i++) cr_grid[r][i] = g3[r][i];
    int rooms3 = count_rooms();

    /* rooms={3,8,1}, sum=12=0x0C, xor=3^8^1=10=0x0A */
    g_result = (3u << 16)
             | ((uint32_t)(rooms1 + rooms2 + rooms3) << 8)
             | (uint32_t)(rooms1 ^ rooms2 ^ rooms3);
}

__attribute__((noreturn)) void _start(void)
{
    test_count_rooms();
    for (;;);
}
