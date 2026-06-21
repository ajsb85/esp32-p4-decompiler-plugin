/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Number of Islands (DFS flood fill) fixture.
 *
 * Count connected components of 1s in a binary grid using DFS flood fill.
 * Each call to dfs marks all reachable 1s as visited then returns.
 *
 * Distinctive decompiler idioms:
 *   1. `if (r<0||r>=R||c<0||c>=C||!grid[r][c]||vis[r][c]) return` — bounds+mark guard
 *   2. `vis[r][c] = 1; dfs(r-1,c); dfs(r+1,c); dfs(r,c-1); dfs(r,c+1)` — 4-connected DFS
 *   3. `islands++; dfs(r,c)` — one DFS per unvisited cell increments island count
 *
 * Grid 1 (4×5, 1 island):   Grid 2 (3×4, 2 islands):  Grid 3 (4×4, 2 islands):
 *  1 1 1 1 0                  1 1 0 0                    1 1 0 0
 *  1 1 0 1 0                  0 1 1 0                    1 1 0 0
 *  1 1 0 0 0                  0 0 0 1                    0 0 1 1
 *  0 0 0 0 0                                             0 0 1 1
 *
 * n_grids    = 3
 * sum_islands = 1 + 2 + 2 = 5
 * xor_islands = 1 ^ 2 ^ 2 = 1
 *
 * g_result = (n_grids << 16) | (sum_islands << 8) | xor_islands = 0x00030501
 */
#include <stdint.h>

volatile uint32_t g_result;

#define NI_MAXR 4
#define NI_MAXC 5

static int ni_vis[NI_MAXR][NI_MAXC];
static int ni_grid[NI_MAXR][NI_MAXC];
static int ni_R, ni_C;

static void ni_dfs(int r, int c)
{
    if (r < 0 || r >= ni_R || c < 0 || c >= ni_C) return;
    if (!ni_grid[r][c] || ni_vis[r][c]) return;
    ni_vis[r][c] = 1;
    ni_dfs(r - 1, c); ni_dfs(r + 1, c);
    ni_dfs(r, c - 1); ni_dfs(r, c + 1);
}

static int ni_count(void)
{
    int cnt = 0;
    for (int r = 0; r < ni_R; r++)
        for (int c = 0; c < ni_C; c++)
            ni_vis[r][c] = 0;
    for (int r = 0; r < ni_R; r++)
        for (int c = 0; c < ni_C; c++)
            if (ni_grid[r][c] && !ni_vis[r][c]) { ni_dfs(r, c); cnt++; }
    return cnt;
}

static const int ni_g1[4][5] = {
    {1,1,1,1,0},{1,1,0,1,0},{1,1,0,0,0},{0,0,0,0,0}
};
static const int ni_g2[3][4] = {
    {1,1,0,0},{0,1,1,0},{0,0,0,1}
};
static const int ni_g3[4][4] = {
    {1,1,0,0},{1,1,0,0},{0,0,1,1},{0,0,1,1}
};

void test_num_islands(void)
{
    uint32_t sum = 0, xor_i = 0;
    int cnt;

    ni_R = 4; ni_C = 5;
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 5; c++) ni_grid[r][c] = ni_g1[r][c];
    cnt = ni_count();
    sum += (uint32_t)cnt; xor_i ^= (uint32_t)cnt;

    ni_R = 3; ni_C = 4;
    for (int r = 0; r < NI_MAXR; r++)
        for (int c = 0; c < NI_MAXC; c++) ni_grid[r][c] = 0;
    for (int r = 0; r < 3; r++)
        for (int c = 0; c < 4; c++) ni_grid[r][c] = ni_g2[r][c];
    cnt = ni_count();
    sum += (uint32_t)cnt; xor_i ^= (uint32_t)cnt;

    ni_R = 4; ni_C = 4;
    for (int r = 0; r < NI_MAXR; r++)
        for (int c = 0; c < NI_MAXC; c++) ni_grid[r][c] = 0;
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++) ni_grid[r][c] = ni_g3[r][c];
    cnt = ni_count();
    sum += (uint32_t)cnt; xor_i ^= (uint32_t)cnt;

    g_result = (3u << 16) | ((sum & 0xFFu) << 8) | (xor_i & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_num_islands();
    for (;;);
}
