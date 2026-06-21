/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Binary Search Tree round-trip fixture.
 *
 * Exercises recursive insert and in-order traversal on a static-pool BST
 * using index-based pointers (int left, right as pool indices) to avoid
 * dynamic allocation in a bare-metal environment.
 *
 * Insertion order: {7, 3, 10, 1, 5, 8, 12, 4}
 * In-order traversal (sorted): {1, 3, 4, 5, 7, 8, 10, 12}
 *
 * Accumulated values:
 *   inorder_xor = 1^3^4^5^7^8^10^12 = 0x0A
 *   inorder_sum = 1+3+4+5+7+8+10+12 = 50 = 0x32
 *
 * g_result = (inorder_sum << 8) | (inorder_xor & 0xFF) = 0x0000320A
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Static BST pool ──────────────────────────────────────────────────────── */

#define BST_MAX 16

typedef struct {
    int key;
    int left;   /* pool index, -1 = no child */
    int right;  /* pool index, -1 = no child */
} BNode;

static BNode bpool[BST_MAX];
static int   bpool_n;

static int bst_alloc(int key)
{
    int i = bpool_n++;
    bpool[i].key   = key;
    bpool[i].left  = -1;
    bpool[i].right = -1;
    return i;
}

static int bst_insert(int root, int key)
{
    if (root < 0) return bst_alloc(key);
    if (key < bpool[root].key)
        bpool[root].left  = bst_insert(bpool[root].left,  key);
    else if (key > bpool[root].key)
        bpool[root].right = bst_insert(bpool[root].right, key);
    return root;
}

/* ── In-order traversal (accumulates xor and sum) ────────────────────────── */

static uint32_t g_xor_acc;
static uint32_t g_sum_acc;

static void bst_inorder(int root)
{
    if (root < 0) return;
    bst_inorder(bpool[root].left);
    g_xor_acc ^= (uint32_t)bpool[root].key;
    g_sum_acc  += (uint32_t)bpool[root].key;
    bst_inorder(bpool[root].right);
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_bst(void)
{
    static const int keys[8] = {7, 3, 10, 1, 5, 8, 12, 4};
    int root = -1;

    bpool_n   = 0;
    g_xor_acc = 0;
    g_sum_acc = 0;

    for (int i = 0; i < 8; i++)
        root = bst_insert(root, keys[i]);

    bst_inorder(root);

    g_result = (g_sum_acc << 8) | (g_xor_acc & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_bst();
    for (;;);
}
