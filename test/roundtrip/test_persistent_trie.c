/*
 * test_persistent_trie.c
 * Persistent binary trie (XOR trie with versioned roots).
 * Each insert creates a new root by copying the spine; old roots are retained.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BITS   20
#define MAXNOD 2048

typedef struct {
    int ch[2];
} TrieNode;

static TrieNode pool[MAXNOD];
static int pool_sz;

/* roots[v] is the root of the trie after inserting values 0..v-1 */
static int roots[64];

static int new_node(void) {
    int id = pool_sz++;
    pool[id].ch[0] = -1;
    pool[id].ch[1] = -1;
    return id;
}

/* Clone node src, return new node id */
static int clone_node(int src) {
    int id = pool_sz++;
    pool[id] = pool[src];
    return id;
}

/* Insert val into trie rooted at prev_root; return new root */
static int ptrie_insert(int prev_root, uint32_t val) {
    int root = (prev_root == -1) ? new_node() : clone_node(prev_root);
    int cur = root;
    for (int b = BITS - 1; b >= 0; b--) {
        int bit = (val >> b) & 1;
        int child;
        if (pool[cur].ch[bit] == -1) {
            child = new_node();
        } else {
            child = clone_node(pool[cur].ch[bit]);
        }
        pool[cur].ch[bit] = child;
        cur = child;
    }
    return root;
}

/* Query max XOR of val against any value in trie rooted at root */
static uint32_t ptrie_max_xor(int root, uint32_t val) {
    if (root == -1) return 0;
    uint32_t res = 0;
    int cur = root;
    for (int b = BITS - 1; b >= 0; b--) {
        int want = ((val >> b) & 1) ^ 1; /* prefer opposite bit */
        if (pool[cur].ch[want] != -1) {
            res |= (1u << b);
            cur = pool[cur].ch[want];
        } else if (pool[cur].ch[want ^ 1] != -1) {
            cur = pool[cur].ch[want ^ 1];
        } else {
            break;
        }
    }
    return res;
}

static uint32_t run_persistent_trie_tests(void) {
    pool_sz = 0;

    /* Build versioned trie: insert values 5, 12, 7, 3 one by one */
    uint32_t vals[] = {5, 12, 7, 3};
    int nv = 4;
    roots[0] = -1;
    for (int i = 0; i < nv; i++) {
        roots[i + 1] = ptrie_insert(roots[i], vals[i]);
    }

    /* Query after inserting first 2 values (5, 12): max XOR with 10 */
    uint32_t q1 = ptrie_max_xor(roots[2], 10u); /* 10 XOR 5=15, 10 XOR 12=6 -> 15 */

    /* Query after inserting all 4 values: max XOR with 6 */
    uint32_t q2 = ptrie_max_xor(roots[4], 6u);  /* 6 XOR 12=10, 6 XOR 3=5 -> 10 */

    /* Pack: n_tests=3, metric_a=q1 (15=0x0F), metric_b=q2 (10=0x0A) */
    uint32_t metric_a = q1 & 0xFF; /* 15 = 0x0F */
    uint32_t metric_b = q2 & 0xFF; /* 10 = 0x0A */
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_persistent_trie_tests();
    while (1) {}
}
