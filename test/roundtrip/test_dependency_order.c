/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Dependency Order (Kahn's BFS toposort) fixture.
 *
 * Generates a valid build order for packages with dependencies using
 * Kahn's BFS algorithm: seed zero-indegree nodes, process and decrement.
 *
 * Distinctive decompiler idioms:
 *   1. `for(i=0;i<n;i++) if(indeg[i]==0) q[back++]=i` — seed queue
 *   2. `if(--indeg[v]==0) q[back++]=v` — decrement and enqueue
 *   3. `pos[order[i]]=i` + edge check `pos[u]<pos[v]` — order validation
 *
 * DAG: 5 packages, edges: 0→1, 0→2, 1→3, 2→3, 3→4
 * Kahn order: 0, 1, 2, 3, 4 (or 0, 2, 1, 3, 4)
 * first=0, last=4, n_edges=5
 *
 * g_result = (n<<16)|(n_edges<<8)|(first*10+last) = 0x00050504
 */
#include <stdint.h>

volatile uint32_t g_result;

#define DO_N  5
#define DO_NE 5

static int do_adj[DO_N][4];
static int do_deg[DO_N];
static int do_indeg[DO_N];

void test_dependency_order(void)
{
    static const int edges[DO_NE][2] = {
        {0,1}, {0,2}, {1,3}, {2,3}, {3,4}
    };
    int order[DO_N], q[DO_N];
    int i, front, back, cnt;

    for (i = 0; i < DO_N; i++) { do_deg[i] = 0; do_indeg[i] = 0; }
    for (i = 0; i < DO_NE; i++) {
        int u = edges[i][0], v = edges[i][1];
        do_adj[u][do_deg[u]++] = v;
        do_indeg[v]++;
    }

    front = back = cnt = 0;
    for (i = 0; i < DO_N; i++)
        if (do_indeg[i] == 0) q[back++] = i;

    while (front < back) {
        int u = q[front++];
        order[cnt++] = u;
        for (i = 0; i < do_deg[u]; i++) {
            int v = do_adj[u][i];
            if (--do_indeg[v] == 0) q[back++] = v;
        }
    }

    /* Verify: pos[u]<pos[v] for each edge */
    int pos[DO_N];
    for (i = 0; i < cnt; i++) pos[order[i]] = i;
    int valid = 1;
    for (i = 0; i < DO_NE; i++) {
        if (pos[edges[i][0]] >= pos[edges[i][1]]) { valid = 0; break; }
    }
    (void)valid;

    /* order[0]=0 (first), order[cnt-1]=4 (last), n_edges=5 */
    g_result = ((uint32_t)DO_N << 16)
             | ((uint32_t)DO_NE << 8)
             | (uint32_t)(order[0] * 10 + order[cnt-1]);
}

__attribute__((noreturn)) void _start(void)
{
    test_dependency_order();
    for (;;);
}
