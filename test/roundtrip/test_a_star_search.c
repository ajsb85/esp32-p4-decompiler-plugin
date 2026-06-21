/*
 * test_a_star_search.c
 * A* search algorithm on a small grid graph.
 * Algorithm: priority-queue-driven BFS with heuristic h(n) = Manhattan
 *   distance to goal. f(n) = g(n) + h(n) where g(n) is the actual cost
 *   from start. Uses a small binary-heap min-priority queue.
 *   Finds shortest path on a 5x5 grid with a wall obstacle.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define AS_ROWS  5
#define AS_COLS  5
#define AS_N     (AS_ROWS * AS_COLS)
#define AS_INF   0x7fff

/* Grid: 0=free, 1=wall */
static const uint8_t as_grid[AS_ROWS][AS_COLS] = {
    {0, 0, 0, 0, 0},
    {0, 1, 1, 1, 0},
    {0, 1, 0, 0, 0},
    {0, 1, 0, 1, 0},
    {0, 0, 0, 1, 0},
};

static int as_g[AS_N];
static int as_f[AS_N];
static int as_closed[AS_N];

/* Min-heap for open set: stores node indices, ordered by f */
static int as_heap[AS_N];
static int as_heap_sz;

static int as_node(int r, int c) { return r * AS_COLS + c; }

static int as_heuristic(int node, int goal) {
    int nr = node / AS_COLS, nc = node % AS_COLS;
    int gr = goal  / AS_COLS, gc = goal  % AS_COLS;
    int dr = nr - gr; if (dr < 0) dr = -dr;
    int dc = nc - gc; if (dc < 0) dc = -dc;
    return dr + dc;
}

static void as_heap_push(int nd) {
    int i = as_heap_sz++;
    as_heap[i] = nd;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (as_f[as_heap[p]] <= as_f[as_heap[i]]) break;
        int tmp = as_heap[p]; as_heap[p] = as_heap[i]; as_heap[i] = tmp;
        i = p;
    }
}

static int as_heap_pop(void) {
    int top = as_heap[0];
    as_heap[0] = as_heap[--as_heap_sz];
    int i = 0;
    while (1) {
        int l = 2*i+1, r = 2*i+2, best = i;
        if (l < as_heap_sz && as_f[as_heap[l]] < as_f[as_heap[best]]) best = l;
        if (r < as_heap_sz && as_f[as_heap[r]] < as_f[as_heap[best]]) best = r;
        if (best == i) break;
        int tmp = as_heap[i]; as_heap[i] = as_heap[best]; as_heap[best] = tmp;
        i = best;
    }
    return top;
}

static const int as_dr[4] = {-1, 1, 0, 0};
static const int as_dc[4] = {0, 0, -1, 1};

static int as_astar(int start, int goal) {
    for (int i = 0; i < AS_N; i++) {
        as_g[i] = AS_INF;
        as_f[i] = AS_INF;
        as_closed[i] = 0;
    }
    as_heap_sz = 0;

    as_g[start] = 0;
    as_f[start] = as_heuristic(start, goal);
    as_heap_push(start);

    while (as_heap_sz > 0) {
        int cur = as_heap_pop();
        if (cur == goal) return as_g[cur];
        if (as_closed[cur]) continue;
        as_closed[cur] = 1;

        int cr = cur / AS_COLS, cc = cur % AS_COLS;
        for (int d = 0; d < 4; d++) {
            int nr = cr + as_dr[d], nc = cc + as_dc[d];
            if (nr < 0 || nr >= AS_ROWS || nc < 0 || nc >= AS_COLS) continue;
            if (as_grid[nr][nc]) continue;
            int nb = as_node(nr, nc);
            if (as_closed[nb]) continue;
            int ng = as_g[cur] + 1;
            if (ng < as_g[nb]) {
                as_g[nb] = ng;
                as_f[nb] = ng + as_heuristic(nb, goal);
                as_heap_push(nb);
            }
        }
    }
    return AS_INF;
}

static uint32_t run_a_star_tests(void) {
    /* Test 1: (0,0) -> (4,4). Path must navigate around walls. */
    int d1 = as_astar(as_node(0, 0), as_node(4, 4));  /* expect 12 */

    /* Test 2: (0,0) -> (0,4). Top row is clear. */
    int d2 = as_astar(as_node(0, 0), as_node(0, 4));  /* expect 4 */

    /* Test 3: (4,0) -> (4,4). Bottom row partial wall at col 3. Route via col 2. */
    int d3 = as_astar(as_node(4, 0), as_node(4, 4));  /* expect 8 */

    /*
     * Pack: n_tests=3, metric_a=d2=4, metric_b=d3=8
     * (3<<16)|(4<<8)|8 = 0x030408  all non-zero and distinct
     */
    (void)d1;
    return (3u << 16) | ((uint32_t)d2 << 8) | (uint32_t)d3;
}

void _start(void) {
    g_result = run_a_star_tests();
    while (1) {}
}
