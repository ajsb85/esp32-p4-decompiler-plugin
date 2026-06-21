/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Hall's Theorem / bipartite perfect matching fixture.
 *
 * Hall's Marriage Theorem: a bipartite graph G=(L∪R, E) with |L|=|R|=n has a
 * perfect matching if and only if for every subset S⊆L, |N(S)| ≥ |S|
 * (where N(S) is the neighbourhood of S in R).
 *
 * This fixture:
 *   1. Implements augmenting-path bipartite matching (Hopcroft-Karp light).
 *   2. Verifies Hall's condition on all 2^n subsets of L (brute-force, n=4).
 *   3. Reports match size and Hall-violation count (0 means perfect matching
 *      guaranteed by Hall's theorem).
 *
 * Graph (L={0,1,2,3}, R={0,1,2,3}):
 *   L0→{R0,R1}, L1→{R1,R2}, L2→{R2,R3}, L3→{R0,R3}
 *   Perfect matching exists: L0→R0, L1→R1, L2→R2, L3→R3  (size=4)
 *   Hall's condition holds for all subsets → hall_violations=0
 *
 * Distinctive decompiler idioms:
 *   1. Bitmask subset enumeration: `for(s=1; s<(1<<n); s++)`
 *   2. Neighbourhood union via OR of bitmask columns
 *   3. Augmenting-path DFS with `match_r[]` and `visited[]` arrays
 *   4. `__builtin_popcount` on bitmask to compare |S| vs |N(S)|
 *
 * g_result = (n<<16)|(match_size<<8)|hall_violations = 0x00040400
 *   n=4, match_size=4, hall_violations=0
 */
#include <stdint.h>

volatile uint32_t g_result;

#define HM_N  4   /* |L| = |R| = 4 */

/* Adjacency bitmask: adj_mask[u] = bitmask of R-nodes reachable from L-node u */
static uint32_t hm_adj[HM_N];

/* Bipartite matching state */
static int hm_match_r[HM_N];   /* match_r[r] = matched L-node, or -1 */
static int hm_visited[HM_N];   /* visited R-nodes during one DFS */

/* ── Augmenting-path DFS ──────────────────────────────────────────────────── */

static int hm_dfs(int u)
{
    for (int r = 0; r < HM_N; r++) {
        if (!(hm_adj[u] & (1u << r))) continue;
        if (hm_visited[r]) continue;
        hm_visited[r] = 1;
        if (hm_match_r[r] < 0 || hm_dfs(hm_match_r[r])) {
            hm_match_r[r] = u;
            return 1;
        }
    }
    return 0;
}

/* ── Count matching size ──────────────────────────────────────────────────── */

static int hm_match(void)
{
    for (int r = 0; r < HM_N; r++) hm_match_r[r] = -1;
    int sz = 0;
    for (int u = 0; u < HM_N; u++) {
        for (int r = 0; r < HM_N; r++) hm_visited[r] = 0;
        if (hm_dfs(u)) sz++;
    }
    return sz;
}

/* ── Verify Hall's condition over all non-empty subsets of L ─────────────── */

static int hm_hall_violations(void)
{
    int violations = 0;
    for (uint32_t s = 1; s < (1u << HM_N); s++) {
        /* |S| */
        int s_size = 0;
        uint32_t tmp = s;
        while (tmp) { s_size += (int)(tmp & 1u); tmp >>= 1; }

        /* N(S): union of neighbours of all L-nodes in S */
        uint32_t nbr = 0;
        for (int u = 0; u < HM_N; u++)
            if (s & (1u << u)) nbr |= hm_adj[u];

        /* |N(S)| */
        int nbr_size = 0;
        tmp = nbr;
        while (tmp) { nbr_size += (int)(tmp & 1u); tmp >>= 1; }

        if (nbr_size < s_size) violations++;
    }
    return violations;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_hall_theorem_matching(void)
{
    /* L0→{R0,R1}, L1→{R1,R2}, L2→{R2,R3}, L3→{R0,R3} */
    hm_adj[0] = (1u << 0) | (1u << 1);
    hm_adj[1] = (1u << 1) | (1u << 2);
    hm_adj[2] = (1u << 2) | (1u << 3);
    hm_adj[3] = (1u << 0) | (1u << 3);

    int match_size      = hm_match();
    int hall_violations = hm_hall_violations();

    /* match_size=4, hall_violations=0 → g_result = 0x00040400 */
    g_result = ((uint32_t)HM_N << 16)
             | ((uint32_t)match_size << 8)
             | (uint32_t)hall_violations;
}

__attribute__((noreturn)) void _start(void)
{
    test_hall_theorem_matching();
    for (;;);
}
