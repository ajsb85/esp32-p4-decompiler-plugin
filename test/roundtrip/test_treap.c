/*
 * test_treap.c — Treap: BST ordered by key, max-heap ordered by priority.
 *
 * Insert keys {5,3,7,1,4,6,8} with fixed priorities {10,40,20,30,50,15,25}.
 * After all insertions root = key 4 (highest priority 50).
 * Inorder traversal yields keys sorted: {1,3,4,5,6,7,8}.
 *
 * n=7, sum_keys=34=0x22, root_key=4=0x04
 * g_result = (7<<16)|(34<<8)|4 = 0x00072204
 */
#include <stdint.h>

#define POOL_CAP 16

typedef struct {
    int key;
    int pri;
    int left;   /* index into pool, -1 = none */
    int right;
} TNode;

static TNode pool[POOL_CAP];
static int   psize;

static int new_node(int key, int pri)
{
    pool[psize].key   = key;
    pool[psize].pri   = pri;
    pool[psize].left  = -1;
    pool[psize].right = -1;
    return psize++;
}

static int right_rot(int r)
{
    int l         = pool[r].left;
    pool[r].left  = pool[l].right;
    pool[l].right = r;
    return l;
}

static int left_rot(int r)
{
    int ri         = pool[r].right;
    pool[r].right  = pool[ri].left;
    pool[ri].left  = r;
    return ri;
}

static int treap_insert(int r, int key, int pri)
{
    if (r == -1) return new_node(key, pri);
    if (key < pool[r].key) {
        pool[r].left = treap_insert(pool[r].left, key, pri);
        if (pool[pool[r].left].pri > pool[r].pri)
            r = right_rot(r);
    } else {
        pool[r].right = treap_insert(pool[r].right, key, pri);
        if (pool[pool[r].right].pri > pool[r].pri)
            r = left_rot(r);
    }
    return r;
}

static int inorder_sum;
static void inorder(int r)
{
    if (r == -1) return;
    inorder(pool[r].left);
    inorder_sum += pool[r].key;
    inorder(pool[r].right);
}

volatile uint32_t g_result;

void test_treap(void)
{
    static const int keys[7] = {5, 3, 7, 1, 4, 6, 8};
    static const int pris[7] = {10,40,20,30,50,15,25};
    int n = 7;

    psize = 0;
    int root = -1;
    for (int i = 0; i < n; i++)
        root = treap_insert(root, keys[i], pris[i]);

    inorder_sum = 0;
    inorder(root);

    g_result = ((uint32_t)n                  << 16)
             | ((uint32_t)inorder_sum         <<  8)
             | ((uint32_t)pool[root].key & 0xFFu);
    /* expected: (7<<16)|(34<<8)|4 = 0x00072204 */
}

__attribute__((noreturn)) void _start(void)
{
    test_treap();
    for (;;);
}
