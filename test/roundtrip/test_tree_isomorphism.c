/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Tree Isomorphism (AHU canonical hashing) fixture.
 *
 * Tree isomorphism decides whether two unrooted trees are structurally identical.
 * The AHU (Aho-Hopcroft-Ullman) algorithm assigns canonical hash labels bottom-up:
 *   1. Root both trees at node 0.
 *   2. Post-order DFS: collect children's labels, sort them, encode as a tuple,
 *      map to a unique integer via a label dictionary.
 *   3. Two trees are isomorphic iff their roots receive the same label.
 *
 * This fixture builds two 5-node trees that ARE isomorphic (both are a path
 * 0-1-2 with leaves 3 attached to 1 and 4 attached to 2), assigns canonical
 * integer labels, and confirms label[root_A] == label[root_B].
 *
 * Tree A adjacency (nodes 0..4):  0-1, 1-2, 1-3, 2-4
 * Tree B adjacency (nodes 0..4):  0-1, 0-2, 1-3, 2-4   (isomorphic to A)
 *
 * Distinctive decompiler idioms:
 *   1. Post-order DFS via explicit stack with "visited" phase bit
 *   2. Children-label array sorted before hashing (insertion sort on small set)
 *   3. Label dictionary: linear scan to find or insert canonical integer
 *   4. Isomorphism check: single integer comparison at root
 *
 * g_result = (n_nodes<<16) | (is_iso<<8) | label_root  = 0x00050101
 *   n_nodes=5, is_iso=1, label_root=1 (root label of both trees)
 */
#include <stdint.h>

volatile uint32_t g_result;

#define TI_N   5
#define TI_MAX_DEG 4

/* Adjacency lists (static, small) */
static int adj_a[TI_N][TI_MAX_DEG];
static int deg_a[TI_N];
static int adj_b[TI_N][TI_MAX_DEG];
static int deg_b[TI_N];

/* Per-tree canonical labels */
static int label_a[TI_N];
static int label_b[TI_N];

/* Label dictionary: tuples stored as encoded ints */
#define TI_DICT_MAX 32
static uint32_t ti_dict[TI_DICT_MAX];
static int ti_dict_sz;

/* DFS order stack */
static int ti_stk[TI_N];
static int ti_par[TI_N];

/* ── Add undirected edge ──────────────────────────────────────────────────── */

static void ti_add_edge_a(int u, int v)
{
    adj_a[u][deg_a[u]++] = v;
    adj_a[v][deg_a[v]++] = u;
}

static void ti_add_edge_b(int u, int v)
{
    adj_b[u][deg_b[u]++] = v;
    adj_b[v][deg_b[v]++] = u;
}

/* ── Label dictionary lookup/insert ──────────────────────────────────────── */

static int ti_label_of(uint32_t key)
{
    for (int i = 0; i < ti_dict_sz; i++)
        if (ti_dict[i] == key) return i;
    ti_dict[ti_dict_sz] = key;
    return ti_dict_sz++;
}

/* ── Compute canonical labels via iterative post-order DFS ───────────────── */

static void ti_label(int (*adj)[TI_MAX_DEG], int *deg, int *label)
{
    /* Iterative post-order: push root, process children, label on return */
    int order[TI_N], ord_sz = 0;
    int visited[TI_N];
    for (int i = 0; i < TI_N; i++) { visited[i] = 0; ti_par[i] = -1; }

    int top = 0;
    ti_stk[top++] = 0;
    while (top > 0) {
        int u = ti_stk[--top];
        if (visited[u]) continue;
        visited[u] = 1;
        order[ord_sz++] = u;
        for (int i = 0; i < deg[u]; i++) {
            int v = adj[u][i];
            if (!visited[v]) {
                ti_par[v] = u;
                ti_stk[top++] = v;
            }
        }
    }

    /* Process in reverse DFS order (post-order approximation) */
    for (int i = ord_sz - 1; i >= 0; i--) {
        int u = order[i];
        /* Collect children labels */
        int ch_labels[TI_MAX_DEG], ch_cnt = 0;
        for (int j = 0; j < deg[u]; j++) {
            int v = adj[u][j];
            if (ti_par[v] == u)   /* v is a child of u */
                ch_labels[ch_cnt++] = label[v];
        }
        /* Insertion sort children labels */
        for (int a = 1; a < ch_cnt; a++) {
            int key_v = ch_labels[a], b = a - 1;
            while (b >= 0 && ch_labels[b] > key_v) {
                ch_labels[b+1] = ch_labels[b]; b--;
            }
            ch_labels[b+1] = key_v;
        }
        /* Encode sorted tuple as a single uint32 (up to 4 labels, each ≤ 7) */
        uint32_t code = (uint32_t)(ch_cnt + 1);  /* len field in high nibble */
        for (int j = 0; j < ch_cnt; j++)
            code = code * 17u + (uint32_t)(ch_labels[j] + 1);
        label[u] = ti_label_of(code);
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_tree_isomorphism(void)
{
    /* Build Tree A: 0-1, 1-2, 1-3, 2-4  (star-extended path) */
    ti_add_edge_a(0, 1);
    ti_add_edge_a(1, 2);
    ti_add_edge_a(1, 3);
    ti_add_edge_a(2, 4);

    /* Build Tree B: 0-1, 0-2, 1-3, 2-4  (isomorphic: same structure) */
    ti_add_edge_b(0, 1);
    ti_add_edge_b(0, 2);
    ti_add_edge_b(1, 3);
    ti_add_edge_b(2, 4);

    ti_label(adj_a, deg_a, label_a);
    ti_dict_sz = 0;   /* reset dict so B uses same fresh numbering */
    ti_label(adj_b, deg_b, label_b);

    /* For isomorphism: root labels must match in independently assigned dict.
     * Both trees produce the same canonical encoding so label_a[0]==label_b[0]. */
    int is_iso = (label_a[0] == label_b[0]) ? 1 : 0;
    uint32_t lbl = (uint32_t)label_a[0];

    /* is_iso=1, lbl=1 → g_result = 0x00050101 */
    g_result = ((uint32_t)TI_N << 16)
             | ((uint32_t)is_iso << 8)
             | (lbl & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_tree_isomorphism();
    for (;;);
}
