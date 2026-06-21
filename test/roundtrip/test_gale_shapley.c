/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Gale-Shapley Stable Matching fixture.
 *
 * The Gale-Shapley algorithm finds a stable matching in the two-sided
 * stable marriage problem.  In the men-proposing variant each free man
 * proposes to his next-best woman; she accepts if she prefers him to her
 * current partner (if any), who is then released as free.  The algorithm
 * terminates with a men-optimal stable matching in O(n²) proposals.
 *
 * Distinctive decompiler idioms:
 *   1. `gs_next[m]++` — advancing the proposal pointer per-man
 *   2. `if (woman_rank[w][m] < woman_rank[w][m2])` — woman preference check
 *   3. `gs_match_m[m2] = -1` — freeing the displaced man
 *   4. `free_count` as loop sentinel (men propose until all matched)
 *   5. 2D `woman_rank[w][m]` for O(1) preference queries
 *
 * Parameters: n = 4 men and women
 * man_pref:
 *   M0: {W1, W0, W2, W3}   M1: {W0, W2, W1, W3}
 *   M2: {W0, W1, W3, W2}   M3: {W2, W3, W1, W0}
 * woman_rank (lower rank = more preferred):
 *   W0: M2>M1>M0>M3        W1: M0>M2>M3>M1
 *   W2: M3>M0>M2>M1        W3: M1>M3>M2>M0
 *
 * Result: M0→W1, M1→W3, M2→W0, M3→W2 (stable, men-optimal)
 * n_proposals = 7 (M1 needs 4 rounds, M2 needs 2, M3 needs 2)
 * match_sum   = 1+3+0+2 = 6
 *
 * g_result = (GS_N << 16) | (n_proposals << 8) | match_sum = 0x040706 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define GS_N 4

static const int gs_man_pref[GS_N][GS_N] = {
    {1, 0, 2, 3},
    {0, 2, 1, 3},
    {0, 1, 3, 2},
    {2, 3, 1, 0}
};

/* woman_rank[w][m]: rank of man m in woman w's preference (0 = most preferred) */
static const int gs_woman_rank[GS_N][GS_N] = {
    {2, 1, 0, 3},   /* W0 prefers M2>M1>M0>M3 */
    {0, 3, 1, 2},   /* W1 prefers M0>M2>M3>M1 */
    {1, 3, 2, 0},   /* W2 prefers M3>M0>M2>M1 */
    {3, 0, 2, 1},   /* W3 prefers M1>M3>M2>M0 */
};

static int gs_match_m[GS_N]; /* gs_match_m[m] = woman matched to m, -1 if free */
static int gs_match_w[GS_N]; /* gs_match_w[w] = man matched to w,   -1 if free */
static int gs_next[GS_N];    /* proposal pointer: next woman index for each man */

void test_gale_shapley(void)
{
    for (int i = 0; i < GS_N; i++) {
        gs_match_m[i] = -1;
        gs_match_w[i] = -1;
        gs_next[i]    = 0;
    }

    int n_proposals = 0;
    int free_count  = GS_N;

    while (free_count > 0) {
        int m = -1;
        for (int i = 0; i < GS_N; i++)
            if (gs_match_m[i] < 0) { m = i; break; }
        if (m < 0) break;

        int w = gs_man_pref[m][gs_next[m]++];
        n_proposals++;

        if (gs_match_w[w] < 0) {
            gs_match_m[m] = w;
            gs_match_w[w] = m;
            free_count--;
        } else {
            int m2 = gs_match_w[w];
            if (gs_woman_rank[w][m] < gs_woman_rank[w][m2]) {
                gs_match_m[m]  = w;
                gs_match_w[w]  = m;
                gs_match_m[m2] = -1;
            }
        }
    }

    int match_sum = 0;
    for (int m = 0; m < GS_N; m++) match_sum += gs_match_m[m];
    /* n_proposals=7, match_sum=6 */

    g_result = ((uint32_t)GS_N       << 16)
             | ((uint32_t)n_proposals <<  8)
             | ((uint32_t)match_sum   & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_gale_shapley();
    for (;;);
}
