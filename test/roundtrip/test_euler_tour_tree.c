/* test_euler_tour_tree.c
 * Purpose   : Validate Euler Tour Tree (ETT) subtree-sum via entry/exit timestamps
 * Algorithm : Perform a DFS-based Euler tour on a rooted tree, recording entry
 *             (tin) and exit (tout) times.  A subtree rooted at v contains all
 *             nodes u where tin[v] <= tin[u] <= tout[v].  We then answer a
 *             subtree-sum query for each node and check the root (node 0) sum,
 *             which must equal the total of all node values.
 * Tree (5 nodes, root=0):
 *       0 (val=1)
 *      / \
 *     1   2  (val=2, val=3)
 *    / \
 *   3   4   (val=4, val=5)
 * Expected  : tout[root] - tin[root] + 1 = 5 (all nodes in root subtree)
 *             n_nodes = 5, sum_root_sub = 1+2+3+4+5 = 15, max_tin = 4
 * g_result  = (n_nodes<<16) | ((sum_root_sub & 0xFF)<<8) | max_tin
 *           = (5<<16) | (15<<8) | 4 = 0x050F04
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define ETT_N  5
#define ETT_NO_CHILD (-1)

static int ett_val[ETT_N]    = {1, 2, 3, 4, 5};
/* adjacency list (children only – tree is rooted at 0) */
static int ett_ch[ETT_N][2]  = {{1,2},{3,4},{ETT_NO_CHILD,ETT_NO_CHILD},
                                  {ETT_NO_CHILD,ETT_NO_CHILD},{ETT_NO_CHILD,ETT_NO_CHILD}};

static int ett_tin[ETT_N];
static int ett_tout[ETT_N];
static int ett_order[ETT_N]; /* DFS visit order */
static int ett_timer;
static int ett_order_cnt;

/* Iterative DFS to avoid deep stack on embedded target */
static int ett_stack[ETT_N * 2];
static int ett_phase[ETT_N * 2]; /* 0=enter, 1=exit */

static void ett_dfs(void) {
    int sp = 0;
    ett_stack[sp] = 0; ett_phase[sp] = 0; sp++;
    while (sp > 0) {
        sp--;
        int v = ett_stack[sp];
        int ph = ett_phase[sp];
        if (ph == 0) {
            ett_tin[v] = ett_timer++;
            ett_order[ett_order_cnt++] = v;
            /* push exit marker */
            ett_stack[sp] = v; ett_phase[sp] = 1; sp++;
            /* push children right-to-left so left child processed first */
            for (int c = 1; c >= 0; c--) {
                int ch = ett_ch[v][c];
                if (ch != ETT_NO_CHILD) {
                    ett_stack[sp] = ch; ett_phase[sp] = 0; sp++;
                }
            }
        } else {
            ett_tout[v] = ett_timer - 1;
        }
    }
}

static int ett_subtree_sum(int v) {
    int s = 0;
    for (int i = 0; i < ETT_N; i++) {
        if (ett_tin[i] >= ett_tin[v] && ett_tin[i] <= ett_tout[v])
            s += ett_val[i];
    }
    return s;
}

void _start(void) {
    ett_timer = 0;
    ett_order_cnt = 0;
    ett_dfs();

    int sum_root = ett_subtree_sum(0);
    int max_tin = 0;
    for (int i = 0; i < ETT_N; i++)
        if (ett_tin[i] > max_tin) max_tin = ett_tin[i];

    g_result = ((uint32_t)ETT_N << 16) |
               ((uint32_t)(sum_root & 0xFF) << 8) |
               (uint32_t)(max_tin & 0xFF);
    while (1) {}
}
