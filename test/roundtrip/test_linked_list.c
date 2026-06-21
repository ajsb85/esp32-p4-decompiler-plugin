/* SPDX-License-Identifier: Apache-2.0
 * Extended round-trip test: singly-linked list.
 *
 * Uses a static node pool (no heap) for bare-metal compatibility.
 * Exercises: struct access via pointer, pointer arithmetic, while-loop
 *            traversal, NULL sentinel.
 *
 * Expected pattern detection: linked_list (pointer-following while loop)
 *
 * Operations:
 *   Push 5 values: 10, 20, 30, 40, 50
 *   Pop  3 values:                50, 40, 30
 *   Traverse remaining: 10 → 20 (XOR = 0x0A ^ 0x14 = 0x1E)
 *   sum_popped = 50+40+30 = 120 = 0x78
 *   g_result = (sum_popped << 8) | traverse_xor = 0x781E
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Static node pool — avoids malloc in bare-metal context */
#define POOL_SIZE 8
typedef struct Node {
    uint32_t     val;
    struct Node *next;
} Node;

static Node s_pool[POOL_SIZE];
static int  s_pool_top = 0;

static Node *node_alloc(uint32_t v) {
    if (s_pool_top >= POOL_SIZE) return (Node *)0;
    Node *n = &s_pool[s_pool_top++];
    n->val  = v;
    n->next = (Node *)0;
    return n;
}

/* Stack implemented as a singly-linked list (push to head) */
typedef struct { Node *head; uint32_t count; } SList;

static void sl_push(SList *sl, uint32_t v) {
    Node *n = node_alloc(v);
    if (!n) return;
    n->next  = sl->head;
    sl->head = n;
    sl->count++;
}

static uint32_t sl_pop(SList *sl) {
    if (!sl->head) return 0;
    uint32_t v   = sl->head->val;
    sl->head     = sl->head->next;
    sl->count--;
    return v;
}

/* XOR-checksum of all remaining nodes via pointer traversal */
static uint32_t sl_checksum(const SList *sl) {
    uint32_t acc = 0;
    const Node *cur = sl->head;
    while (cur) {
        acc ^= cur->val;
        cur  = cur->next;
    }
    return acc;
}

void _start(void) {
    SList sl = { .head = (Node *)0, .count = 0 };

    sl_push(&sl, 10);
    sl_push(&sl, 20);
    sl_push(&sl, 30);
    sl_push(&sl, 40);
    sl_push(&sl, 50);

    uint32_t sum_popped = sl_pop(&sl) + sl_pop(&sl) + sl_pop(&sl);
    /* = 50 + 40 + 30 = 120 = 0x78 */

    uint32_t xor_remain = sl_checksum(&sl);
    /* remaining: 20 → 10, xor = 0x14 ^ 0x0A = 0x1E */

    g_result = (sum_popped << 8) | (xor_remain & 0xFFu);
    /* = (0x78 << 8) | 0x1E = 0x00007800 | 0x1E = 0x0000781E */

    for (;;);
}
