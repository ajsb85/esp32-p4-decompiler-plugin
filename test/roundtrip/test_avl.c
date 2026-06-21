/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — AVL (height-balanced BST) round-trip fixture.
 *
 * Exercises rotations (LL, RR, LR, RL) and balance-factor maintenance on a
 * static-pool AVL tree with index-based child links.  Rotation idioms are
 * highly recognisable in decompiled output (height field update + two-step
 * child pointer swap).
 *
 * Insertion order: {3, 1, 4, 5, 9, 2, 6}
 *
 * Rotation trace:
 *   After inserting 9 → node 4 becomes right-heavy (balance=-2, RR case)
 *   → left-rotate at 4 → subtree root becomes 5 with children {4, 9}
 *   No further rotations for keys {2, 6}.
 *
 * Final tree (in-order sorted):
 *       3
 *      / \
 *     1   5
 *      \  / \
 *       2 4   9
 *            /
 *           6
 *
 * In-order traversal: {1, 2, 3, 4, 5, 6, 9}
 *   in_xor = 1^2^3^4^5^6^9 = 0x0E
 *   in_sum = 1+2+3+4+5+6+9 = 30 = 0x1E
 *   node_count = 7
 *
 * g_result = (node_count << 16) | (in_sum << 8) | in_xor = 0x00071E0E
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Static AVL pool ──────────────────────────────────────────────────────── */

#define AVL_MAX 16

typedef struct {
    int key, left, right, height;
} ANode;

static ANode apool[AVL_MAX];
static int   apool_n;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int avl_height(int n)
{
    return (n < 0) ? -1 : apool[n].height;
}

static int avl_balance(int n)
{
    return (n < 0) ? 0 : avl_height(apool[n].left) - avl_height(apool[n].right);
}

static void avl_update_height(int n)
{
    if (n < 0) return;
    int hl = avl_height(apool[n].left);
    int hr = avl_height(apool[n].right);
    apool[n].height = (hl > hr ? hl : hr) + 1;
}

/* ── Rotations ──────────────────────────────────────────────────────────── */

static int avl_rotate_right(int y)
{
    int x  = apool[y].left;
    int t2 = apool[x].right;
    apool[x].right = y;
    apool[y].left  = t2;
    avl_update_height(y);
    avl_update_height(x);
    return x;
}

static int avl_rotate_left(int x)
{
    int y  = apool[x].right;
    int t2 = apool[y].left;
    apool[y].left  = x;
    apool[x].right = t2;
    avl_update_height(x);
    avl_update_height(y);
    return y;
}

/* ── Insert ──────────────────────────────────────────────────────────────── */

static int avl_insert(int n, int key)
{
    if (n < 0) {
        int i = apool_n++;
        apool[i].key    = key;
        apool[i].left   = -1;
        apool[i].right  = -1;
        apool[i].height = 0;
        return i;
    }

    if (key < apool[n].key)
        apool[n].left  = avl_insert(apool[n].left,  key);
    else if (key > apool[n].key)
        apool[n].right = avl_insert(apool[n].right, key);
    else
        return n; /* duplicate — ignored */

    avl_update_height(n);

    int bal = avl_balance(n);

    /* LL: left subtree is left-heavy */
    if (bal > 1 && key < apool[apool[n].left].key)
        return avl_rotate_right(n);

    /* RR: right subtree is right-heavy */
    if (bal < -1 && key > apool[apool[n].right].key)
        return avl_rotate_left(n);

    /* LR: left subtree is right-heavy */
    if (bal > 1 && key > apool[apool[n].left].key) {
        apool[n].left = avl_rotate_left(apool[n].left);
        return avl_rotate_right(n);
    }

    /* RL: right subtree is left-heavy */
    if (bal < -1 && key < apool[apool[n].right].key) {
        apool[n].right = avl_rotate_right(apool[n].right);
        return avl_rotate_left(n);
    }

    return n;
}

/* ── In-order traversal ──────────────────────────────────────────────────── */

static uint32_t g_avl_xor;
static uint32_t g_avl_sum;

static void avl_inorder(int n)
{
    if (n < 0) return;
    avl_inorder(apool[n].left);
    g_avl_xor ^= (uint32_t)apool[n].key;
    g_avl_sum  += (uint32_t)apool[n].key;
    avl_inorder(apool[n].right);
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_avl(void)
{
    static const int keys[7] = {3, 1, 4, 5, 9, 2, 6};
    int root = -1;

    apool_n   = 0;
    g_avl_xor = 0;
    g_avl_sum = 0;

    for (int i = 0; i < 7; i++)
        root = avl_insert(root, keys[i]);

    avl_inorder(root);

    g_result = ((uint32_t)apool_n << 16)
             | (g_avl_sum << 8)
             | (g_avl_xor & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_avl();
    for (;;);
}
