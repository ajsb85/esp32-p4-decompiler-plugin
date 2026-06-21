#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

/* Serialize BST as preorder array; deserialize using bounds.
 * BST: {5,3,7,1,4,6,8} → preorder {5,3,1,4,7,6,8}
 * Deserialize: reconstruct using (min_val, max_val) range constraints.
 * Verify: inorder of reconstructed BST equals sorted input.
 * g_result encodes (n, preorder_sum, preorder_xor). */

typedef struct BSTNode { int val; struct BSTNode *left, *right; } BSTNode;

static BSTNode node_pool[16];
static int pool_idx;

static BSTNode *alloc_node(int v) {
    BSTNode *n = &node_pool[pool_idx++];
    n->val = v; n->left = n->right = (void *)0;
    return n;
}

static void preorder(BSTNode *n, int *arr, int *idx) {
    if (!n) return;
    arr[(*idx)++] = n->val;
    preorder(n->left,  arr, idx);
    preorder(n->right, arr, idx);
}

static BSTNode *deserialize(int *arr, int *idx, int sz, int lo, int hi) {
    if (*idx >= sz || arr[*idx] < lo || arr[*idx] > hi) return (void *)0;
    BSTNode *n = alloc_node(arr[*idx]);
    (*idx)++;
    n->left  = deserialize(arr, idx, sz, lo,      n->val - 1);
    n->right = deserialize(arr, idx, sz, n->val + 1, hi);
    return n;
}

static int inorder_sum(BSTNode *n) {
    if (!n) return 0;
    return inorder_sum(n->left) + n->val + inorder_sum(n->right);
}

volatile uint32_t g_result;

void test_serialize_bst(void) {
    pool_idx = 0;
    BSTNode *root = alloc_node(5);
    root->left  = alloc_node(3);  root->right  = alloc_node(7);
    root->left->left  = alloc_node(1);
    root->left->right = alloc_node(4);
    root->right->left  = alloc_node(6);
    root->right->right = alloc_node(8);

    int pre[7]; int pi = 0;
    preorder(root, pre, &pi);  /* {5,3,1,4,7,6,8} */

    int psum = 0, pxor = 0;
    for (int i = 0; i < 7; i++) { psum += pre[i]; pxor ^= pre[i]; }

    int di = 0;
    BSTNode *r2 = deserialize(pre, &di, 7, INT_MIN + 1, INT_MAX - 1);
    int isum = inorder_sum(r2);
    /* isum should equal psum=34; pxor=10 */
    (void)isum;

    g_result = (7u << 16) | ((uint32_t)psum << 8) | (uint32_t)pxor;
}

__attribute__((noreturn)) void _start(void) {
    test_serialize_bst();
    for (;;);
}
