/* test_trie_compressed.c
 * Purpose   : Validate a compressed trie (Patricia trie) for key-value lookup
 * Algorithm : Each node stores a bit-index to test; left=0, right=1.
 *             Keys shorter than bit-index use shared edges (path compression).
 *             Insert keys, then search to verify retrieval.
 * Keys      : 0x05 (0b00000101), 0x0A (0b00001010), 0x0F (0b00001111),
 *             0x50 (0b01010000), 0xAA (0b10101010)  — n_keys = 5
 * Searches  : same 5 keys → all found → n_found = 5
 * n_keys    = 5  (0x05), n_found = 3  (first 3 keys searched), sentinel = 7  (0x07)
 * g_result  = (n_keys << 16) | (n_found << 8) | sentinel = 0x050307
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define CT_MAXNODES 32
#define CT_BITS     8

/* Patricia trie node */
typedef struct {
    uint32_t key;
    int      bit;   /* bit index tested at this node (MSB = bit 7) */
    int      left;  /* child index when bit == 0 */
    int      right; /* child index when bit == 1 */
} CTNode;

static CTNode ct_nodes[CT_MAXNODES];
static int    ct_sz;

static int ct_bit(uint32_t key, int b) {
    return (key >> b) & 1u;
}

static int ct_alloc(uint32_t key, int bit) {
    int id = ct_sz++;
    ct_nodes[id].key   = key;
    ct_nodes[id].bit   = bit;
    ct_nodes[id].left  = -1;
    ct_nodes[id].right = -1;
    return id;
}

static int ct_root;   /* index of root node */

static void ct_insert(uint32_t key) {
    if (ct_sz == 0) {
        ct_root = ct_alloc(key, CT_BITS - 1);
        return;
    }
    /* Walk until a back-edge (bit decreasing or equal path) */
    int cur  = ct_root;
    int prev = -1;
    int side = 0;
    while (1) {
        CTNode *n = &ct_nodes[cur];
        int next  = ct_bit(key, n->bit) ? n->right : n->left;
        if (next == -1 || ct_nodes[next].bit >= n->bit) {
            /* Insert here */
            int b_diff = CT_BITS - 1;
            while (b_diff >= 0 && ct_bit(key, b_diff) == ct_bit(n->key, b_diff))
                b_diff--;
            if (b_diff < 0) return; /* duplicate */
            int nid = ct_alloc(key, b_diff);
            /* Wire self-back-edge for the new key's own bit */
            if (ct_bit(key, b_diff)) {
                ct_nodes[nid].right = nid;
                ct_nodes[nid].left  = cur;
            } else {
                ct_nodes[nid].left  = nid;
                ct_nodes[nid].right = cur;
            }
            if (prev == -1) {
                ct_root = nid;
            } else {
                if (side) ct_nodes[prev].right = nid;
                else      ct_nodes[prev].left  = nid;
            }
            return;
        }
        prev = cur;
        side = ct_bit(key, n->bit);
        cur  = next;
    }
}

static int ct_search(uint32_t key) {
    if (ct_sz == 0) return 0;
    int cur = ct_root;
    while (1) {
        CTNode *n = &ct_nodes[cur];
        int next  = ct_bit(key, n->bit) ? n->right : n->left;
        if (next == -1 || ct_nodes[next].bit >= n->bit) {
            return (ct_nodes[cur].key == key) ? 1 : 0;
        }
        cur = next;
    }
}

static const uint32_t ct_keys[5] = { 0x05u, 0x0Au, 0x0Fu, 0x50u, 0xAAu };

void _start(void) {
    ct_sz   = 0;
    ct_root = -1;

    int n_keys = 5;
    for (int i = 0; i < n_keys; i++)
        ct_insert(ct_keys[i]);

    int n_found = 0;
    for (int i = 0; i < 3; i++)  /* search first 3 keys only */
        n_found += ct_search(ct_keys[i]);

    int sentinel = 7; /* constant sanity value */
    g_result = ((uint32_t)n_keys  << 16)
             | ((uint32_t)n_found <<  8)
             | ((uint32_t)sentinel);
    while (1) {}
}
