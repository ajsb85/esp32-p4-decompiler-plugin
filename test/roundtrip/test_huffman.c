/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Huffman Encoding fixture.
 *
 * Huffman coding: build an optimal prefix-free code by repeatedly merging the
 * two lowest-frequency nodes using a priority queue (min-heap/sorted insert).
 *
 * Distinctive decompiler idioms:
 *   1. `find_min()` over active pool — O(n) min extraction
 *   2. `new_node.freq = a.freq + b.freq; new_node.left = a; new_node.right = b`
 *   3. `huf_dfs(node, depth)` — recursive code-length assignment to leaves
 *   4. `total_bits += freq[i] * code_len[i]` — accumulate weighted length
 *
 * Characters (0-indexed): a(5), b(2), c(1), d(3), e(4)
 *
 * Build steps:
 *   Merge c(1)+b(2)=node5(3)
 *   Merge d(3)+node5(3)=node6(6)
 *   Merge e(4)+a(5)=node7(9)
 *   Merge node6(6)+node7(9)=node8(15)  ← root
 *
 * Code lengths: a=2, b=3, c=3, d=2, e=2
 * Total bits = 5*2 + 2*3 + 1*3 + 3*2 + 4*2 = 33
 * xor_lengths = 2^3^3^2^2 = 2
 *
 * n_chars     = 5
 * total_bits  = 33 (0x21)
 * xor_lengths = 2
 *
 * g_result = (n_chars << 16) | (total_bits << 8) | xor_lengths = 0x00052102
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Huffman node pool ───────────────────────────────────────────────────── */

#define HUF_CHARS    5
#define HUF_MAXNODES 9   /* 2*HUF_CHARS - 1 */

struct HufNode {
    int freq, left, right;
};

static struct HufNode huf_nodes[HUF_MAXNODES];
static int            huf_active[HUF_MAXNODES];
static int            huf_n_nodes;
static int            huf_code_len[HUF_CHARS]; /* code length per leaf */

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int huf_find_min(void)
{
    int mf = 0x7fffffff, mi = -1;
    for (int i = 0; i < huf_n_nodes; i++)
        if (huf_active[i] && huf_nodes[i].freq < mf) {
            mf = huf_nodes[i].freq; mi = i;
        }
    return mi;
}

static void huf_dfs(int node, int depth)
{
    if (huf_nodes[node].left == -1) {
        /* leaf node — its index IS the char index for nodes 0..HUF_CHARS-1 */
        huf_code_len[node] = depth;
        return;
    }
    huf_dfs(huf_nodes[node].left,  depth + 1);
    huf_dfs(huf_nodes[node].right, depth + 1);
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_huffman(void)
{
    static const int freqs[HUF_CHARS] = {5, 2, 1, 3, 4};

    huf_n_nodes = HUF_CHARS;
    for (int i = 0; i < HUF_CHARS; i++) {
        huf_nodes[i].freq  = freqs[i];
        huf_nodes[i].left  = -1;
        huf_nodes[i].right = -1;
        huf_active[i]      = 1;
    }
    for (int i = HUF_CHARS; i < HUF_MAXNODES; i++) {
        huf_nodes[i].freq  = 0;
        huf_nodes[i].left  = -1;
        huf_nodes[i].right = -1;
        huf_active[i]      = 0;
    }

    /* Build Huffman tree: merge two minimums until one node remains */
    while (1) {
        int a = huf_find_min();
        if (a < 0) break;
        huf_active[a] = 0;
        int b = huf_find_min();
        if (b < 0) { huf_active[a] = 1; break; }
        huf_active[b] = 0;

        int nn = huf_n_nodes++;
        huf_nodes[nn].freq  = huf_nodes[a].freq + huf_nodes[b].freq;
        huf_nodes[nn].left  = a;
        huf_nodes[nn].right = b;
        huf_active[nn]      = 1;
    }

    /* Assign code lengths via DFS from root */
    int root = huf_n_nodes - 1;
    huf_dfs(root, 0);

    /* Compute total encoded bits and XOR of code lengths */
    int      total_bits = 0;
    uint32_t xor_len    = 0;
    for (int i = 0; i < HUF_CHARS; i++) {
        total_bits += freqs[i] * huf_code_len[i];
        xor_len    ^= (uint32_t)huf_code_len[i];
    }

    /* total_bits=33, xor_len=2 */
    g_result = ((uint32_t)HUF_CHARS << 16)
             | ((uint32_t)(total_bits & 0xFF) << 8)
             | (xor_len & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_huffman();
    for (;;);
}
