/* test_rope_string.c
 * Purpose   : Validate Rope data structure for efficient string split/concat
 * Algorithm : Rope stores a string as a binary tree of substrings.
 *             Each leaf holds a small character array segment; internal nodes
 *             track the total weight (length of left subtree) to support O(log n)
 *             index access, split, and concatenation.
 *             split(root, k) returns (left_rope, right_rope) splitting after char k.
 *             concat(a, b) creates a new internal node with weight = size(a).
 *             Characteristic idioms: `weight = left_size`, recursive split,
 *             node reuse (no deep copy), `if (k <= weight) go left; else go right`.
 * Input     : Build rope from "HELLOWORLD" (10 chars).
 *             Split after position 5 → left="HELLO", right="WORLD".
 *             Concat right+left → "WORLDHELLO".
 *             Read char at index 2 of result → 'R' = 82.
 * g_result  = (n_chars << 16) | (char_val << 8) | split_pos
 *           = (10 << 16) | (82 << 8) | 5   => 0x0A5205
 */
#include <stdint.h>

volatile uint32_t g_result;

#define ROPE_MAX_NODES  32
#define ROPE_LEAF_CAP   8

/* Node types */
#define ROPE_LEAF     0
#define ROPE_INTERNAL 1

typedef struct RopeNode {
    int  type;
    int  weight;     /* length of left subtree (or leaf length if leaf) */
    int  left;       /* index into node pool, -1 if leaf */
    int  right;
    char buf[ROPE_LEAF_CAP]; /* used only for leaf nodes */
} RopeNode;

static RopeNode rp_pool[ROPE_MAX_NODES];
static int      rp_cnt;

static int rp_new_leaf(const char *s, int len) {
    int idx = rp_cnt++;
    rp_pool[idx].type   = ROPE_LEAF;
    rp_pool[idx].weight = len;
    rp_pool[idx].left   = -1;
    rp_pool[idx].right  = -1;
    for (int i = 0; i < len && i < ROPE_LEAF_CAP; i++)
        rp_pool[idx].buf[i] = s[i];
    return idx;
}

static int rp_new_internal(int l, int r) {
    int idx = rp_cnt++;
    rp_pool[idx].type   = ROPE_INTERNAL;
    rp_pool[idx].weight = rp_pool[l].weight; /* weight = size of left subtree */
    rp_pool[idx].left   = l;
    rp_pool[idx].right  = r;
    return idx;
}

/* Return total length of subtree rooted at node */
static int rp_len(int node) {
    if (node < 0) return 0;
    if (rp_pool[node].type == ROPE_LEAF) return rp_pool[node].weight;
    return rp_len(rp_pool[node].left) + rp_len(rp_pool[node].right);
}

/* Index access: return char at position k (0-based) */
static char rp_index(int node, int k) {
    while (rp_pool[node].type == ROPE_INTERNAL) {
        if (k < rp_pool[node].weight) {
            node = rp_pool[node].left;
        } else {
            k -= rp_pool[node].weight;
            node = rp_pool[node].right;
        }
    }
    return rp_pool[node].buf[k];
}

/* Split node at position k: out_left gets first k chars, out_right gets rest */
static void rp_split(int node, int k, int *out_left, int *out_right) {
    if (rp_pool[node].type == ROPE_LEAF) {
        /* Split the leaf */
        int llen = k;
        int rlen = rp_pool[node].weight - k;
        *out_left  = rp_new_leaf(rp_pool[node].buf, llen);
        *out_right = rp_new_leaf(rp_pool[node].buf + llen, rlen);
        return;
    }
    /* Internal node */
    int w = rp_pool[node].weight;
    if (k <= w) {
        int sl, sr;
        rp_split(rp_pool[node].left, k, &sl, &sr);
        *out_left  = sl;
        *out_right = rp_new_internal(sr, rp_pool[node].right);
        /* Fix weight of new internal */
        rp_pool[*out_right].weight = rp_len(rp_pool[*out_right].left);
    } else {
        int sl, sr;
        rp_split(rp_pool[node].right, k - w, &sl, &sr);
        *out_left  = rp_new_internal(rp_pool[node].left, sl);
        rp_pool[*out_left].weight = w;
        *out_right = sr;
    }
}

void test_rope_string(void) {
    rp_cnt = 0;

    /* Build rope from "HELLOWORLD" in two leaf nodes */
    int leaf1 = rp_new_leaf("HELLO", 5);  /* "HELLO" */
    int leaf2 = rp_new_leaf("WORLD", 5);  /* "WORLD" */
    int root  = rp_new_internal(leaf1, leaf2);

    /* Split after position 5 → left_rope="HELLO", right_rope="WORLD" */
    int lrope, rrope;
    rp_split(root, 5, &lrope, &rrope);

    /* Concat right_rope + left_rope → "WORLDHELLO" */
    int combined = rp_new_internal(rrope, lrope);
    rp_pool[combined].weight = rp_len(rrope);

    /* Read char at index 2 of combined → 'R' (0-based: W=0,O=1,R=2) */
    char ch = rp_index(combined, 2);  /* 'R' = 82 */

    int n_chars   = rp_len(root);     /* 10 */
    int char_val  = (int)(unsigned char)ch; /* 82 */
    int split_pos = 5;

    g_result = ((uint32_t)n_chars   << 16)
             | ((uint32_t)char_val  <<  8)
             | (uint32_t)split_pos;
    while (1) {}
}

__attribute__((noreturn)) void _start(void) {
    test_rope_string();
    for (;;);
}
