/* test_bipartite_matching_hopcroft.c
 * Purpose   : Validate Hopcroft-Karp bipartite maximum matching
 * Algorithm : Hopcroft-Karp runs BFS to find shortest augmenting path layers
 *             then DFS to augment multiple disjoint paths simultaneously,
 *             achieving O(E * sqrt(V)) complexity.
 * Input     : Bipartite graph with L={0,1,2,3}, R={0,1,2,3}
 *             Edges: (0,0),(0,1),(1,1),(1,2),(2,2),(2,3),(3,3),(3,0)
 * Expected  : Maximum matching = 4 (perfect matching exists)
 *             One valid matching: 0-0,1-1,2-2,3-3 OR 0-1,1-2,2-3,3-0
 *             n_edges=8, matching_size=4, sum_matched_r=0+1+2+3=6
 * g_result  = (n_edges<<16) | (matching_size<<8) | sum_matched_r
 *           = (8<<16) | (4<<8) | 6 = 0x080406  (bytes 8,4,6 all distinct)
 */

#include <stdint.h>

volatile uint32_t g_result;

#define HK_L 4
#define HK_R 4
#define HK_E 8

/* Adjacency list for left nodes */
static int hk_head[HK_L];
static int hk_to[HK_E];
static int hk_next[HK_E];
static int hk_ecnt;

/* Matching arrays */
static int hk_match_l[HK_L]; /* match_l[u] = matched right node, or -1 */
static int hk_match_r[HK_R]; /* match_r[v] = matched left node, or -1 */
static int hk_dist[HK_L];    /* BFS layer distances */

#define HK_INF 0x7fffffff

static void hk_add(int u, int v) {
    hk_to[hk_ecnt]   = v;
    hk_next[hk_ecnt] = hk_head[u];
    hk_head[u]        = hk_ecnt++;
}

/* BFS: build layered graph, return 1 if augmenting path exists */
static int hk_bfs(void) {
    int queue[HK_L];
    int qh = 0, qt = 0;
    for (int u = 0; u < HK_L; u++) {
        if (hk_match_l[u] == -1) {
            hk_dist[u] = 0;
            queue[qt++] = u;
        } else {
            hk_dist[u] = HK_INF;
        }
    }
    int found = 0;
    while (qh < qt) {
        int u = queue[qh++];
        for (int e = hk_head[u]; e != -1; e = hk_next[e]) {
            int v = hk_to[e];
            int w = hk_match_r[v]; /* left node matched to v */
            if (w == -1) {
                found = 1;
            } else if (hk_dist[w] == HK_INF) {
                hk_dist[w] = hk_dist[u] + 1;
                queue[qt++] = w;
            }
        }
    }
    return found;
}

/* DFS: augment along layered graph */
static int hk_dfs(int u) {
    for (int e = hk_head[u]; e != -1; e = hk_next[e]) {
        int v = hk_to[e];
        int w = hk_match_r[v];
        if (w == -1 || (hk_dist[w] == hk_dist[u] + 1 && hk_dfs(w))) {
            hk_match_l[u] = v;
            hk_match_r[v] = u;
            return 1;
        }
    }
    hk_dist[u] = HK_INF;
    return 0;
}

static int hk_max_matching(void) {
    for (int u = 0; u < HK_L; u++) hk_match_l[u] = -1;
    for (int v = 0; v < HK_R; v++) hk_match_r[v] = -1;

    int matching = 0;
    while (hk_bfs()) {
        for (int u = 0; u < HK_L; u++) {
            if (hk_match_l[u] == -1 && hk_dfs(u)) {
                matching++;
            }
        }
    }
    return matching;
}

void _start(void) {
    /* Initialize adjacency list */
    for (int i = 0; i < HK_L; i++) hk_head[i] = -1;
    hk_ecnt = 0;

    /* Add edges: (0,0),(0,1),(1,1),(1,2),(2,2),(2,3),(3,3),(3,0) */
    hk_add(0, 0); hk_add(0, 1);
    hk_add(1, 1); hk_add(1, 2);
    hk_add(2, 2); hk_add(2, 3);
    hk_add(3, 3); hk_add(3, 0);

    int matching = hk_max_matching();

    int sum_r = 0;
    for (int u = 0; u < HK_L; u++) {
        if (hk_match_l[u] != -1) sum_r += hk_match_l[u];
    }

    /* g_result = (n_left<<16) | (matching<<8) | sum_r
     *          = (4<<16) | (4<<8) | 6 = 0x040406 */
    g_result = ((uint32_t)HK_L    << 16)
             | ((uint32_t)matching << 8)
             |  (uint32_t)sum_r;
    while (1) {}
}
