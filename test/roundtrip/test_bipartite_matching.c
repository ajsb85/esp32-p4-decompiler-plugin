/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Maximum Bipartite Matching (augmenting path) fixture.
 *
 * Finds maximum matching in a bipartite graph using augmenting path DFS
 * (Hungarian algorithm). For each unmatched left node, tries to find an
 * augmenting path through the DFS.
 *
 * Distinctive decompiler idioms:
 *   1. `bpm_try(u): for each v in adj[u]: if !vis[v]: vis[v]=1; if unmatched or augment: match`
 *   2. `for u=0..n_left: memset(vis,0); if bpm_try(u) match++` — driver loop
 *   3. `match_r[v] = u; return 1` — record augmenting match
 *
 * Graph: K_{3,3} complete bipartite (3 left, 3 right, 9 edges)
 *   Maximum matching = 3 (perfect matching)
 *
 * n_edges=9, max_match=3, n_left=3
 * g_result = (n_edges << 16) | (max_match << 8) | n_left = 0x00090303
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BPM_L 3
#define BPM_R 3

static int bpm_match_r[BPM_R]; /* which left node matched to each right */
static int bpm_vis[BPM_R];
/* K_{3,3}: all 3 right nodes for each left */
static const int bpm_adj[BPM_L][BPM_R] = {{0,1,2},{0,1,2},{0,1,2}};

static int bpm_try(int u)
{
    for (int i = 0; i < BPM_R; i++) {
        int v = bpm_adj[u][i];
        if (!bpm_vis[v]) {
            bpm_vis[v] = 1;
            if (bpm_match_r[v] == -1 || bpm_try(bpm_match_r[v])) {
                bpm_match_r[v] = u;
                return 1;
            }
        }
    }
    return 0;
}

void test_bipartite_matching(void)
{
    for (int i = 0; i < BPM_R; i++) bpm_match_r[i] = -1;

    int match = 0;
    for (int u = 0; u < BPM_L; u++) {
        for (int i = 0; i < BPM_R; i++) bpm_vis[i] = 0;
        if (bpm_try(u)) match++;
    }

    g_result = ((uint32_t)(BPM_L * BPM_R) << 16)
             | ((uint32_t)(match & 0xFF) << 8)
             | ((uint32_t)(BPM_L & 0xFF));
}

__attribute__((noreturn)) void _start(void)
{
    test_bipartite_matching();
    for (;;);
}
