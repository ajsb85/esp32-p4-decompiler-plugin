/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Huffman Encoding (heap-based greedy) fixture.
 *
 * Builds a Huffman tree via a min-priority queue (binary min-heap) and
 * computes the total weighted path length (optimal prefix-code cost).
 *
 * Distinctive decompiler idioms:
 *   1. Min-heap sift-down: `while (child < n) { if (right<n && hp[r]<hp[l]) sel=r; swap+sift }`
 *   2. `hp_weight[parent] = hp_weight[left] + hp_weight[right]` — merge step
 *   3. `hp_parent[left] = hp_parent[right] = new_node` — tree link
 *   4. `total += depth * freq[sym]` — weighted external-path accumulation
 *
 * Input: 5 symbols with frequencies {4, 2, 7, 1, 3}
 *   Sorted ascending: 1, 2, 3, 4, 7
 *
 * Huffman tree construction (merge smallest two each round):
 *   Round 1: merge 1+2 → 3 (new node). Heap: {3, 3, 4, 7}
 *   Round 2: merge 3+3 → 6. Heap: {4, 6, 7}
 *   Round 3: merge 4+6 → 10. Heap: {7, 10}
 *   Round 4: merge 7+10 → 17 (root). Done.
 *
 * Optimal code length = sum of all internal node weights = 3+6+10+17 = 36
 *   Equivalently: Σ (depth[leaf] * freq[leaf]).
 *
 * n_syms     = 5
 * total_cost = 36 = 0x24
 * root_weight= 17 = 0x11
 *
 * g_result = (n_syms << 16) | (total_cost << 8) | root_weight = 0x00052411
 */
#include <stdint.h>

volatile uint32_t g_result;

#define HUF_NSYM  5
#define HUF_NODES (2 * HUF_NSYM - 1)  /* 5 leaves + 4 internal = 9 */

/* Min-heap holds node indices; heap ordered by weight. */
static int    huf_w[HUF_NODES];   /* node weights (= freq for leaves) */
static int    huf_heap[HUF_NODES];
static int    huf_hsz;

/* ── Heap helpers ─────────────────────────────────────────────────────────── */

static void heap_push(int idx)
{
    huf_heap[huf_hsz] = idx;
    int i = huf_hsz++;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (huf_w[huf_heap[p]] <= huf_w[huf_heap[i]]) break;
        int tmp = huf_heap[p]; huf_heap[p] = huf_heap[i]; huf_heap[i] = tmp;
        i = p;
    }
}

static int heap_pop(void)
{
    int top = huf_heap[0];
    huf_heap[0] = huf_heap[--huf_hsz];
    int i = 0;
    while (1) {
        int l = 2*i+1, r = 2*i+2, s = i;
        if (l < huf_hsz && huf_w[huf_heap[l]] < huf_w[huf_heap[s]]) s = l;
        if (r < huf_hsz && huf_w[huf_heap[r]] < huf_w[huf_heap[s]]) s = r;
        if (s == i) break;
        int tmp = huf_heap[s]; huf_heap[s] = huf_heap[i]; huf_heap[i] = tmp;
        i = s;
    }
    return top;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_huffman_encode(void)
{
    static const int freq[HUF_NSYM] = {4, 2, 7, 1, 3};

    /* Initialise leaves */
    for (int i = 0; i < HUF_NSYM; i++) {
        huf_w[i] = freq[i];
        heap_push(i);
    }

    int node_cnt = HUF_NSYM;
    int total_cost = 0;

    /* Greedy merge: extract two minimum-weight nodes, merge into new internal node */
    while (huf_hsz > 1) {
        int a = heap_pop();
        int b = heap_pop();
        int merged = node_cnt++;
        huf_w[merged] = huf_w[a] + huf_w[b];
        total_cost += huf_w[merged];  /* sum of all internal node weights = code length */
        heap_push(merged);
    }
    int root = heap_pop();  /* root node */

    /* total_cost = 36, root_weight = 17 */
    g_result = ((uint32_t)HUF_NSYM     << 16)
             | ((uint32_t)total_cost   << 8)
             | ((uint32_t)huf_w[root] & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_huffman_encode();
    for (;;);
}
