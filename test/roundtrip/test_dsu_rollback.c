/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — DSU with Rollback fixture.
 *
 * Standard DSU (union-by-rank) extended with an explicit undo stack.
 * Path compression is OMITTED — it would make rollback impossible.
 *
 * Distinctive decompiler idioms:
 *   1. `while (dr_p[x] != x) x = dr_p[x]` — find WITHOUT path compression
 *   2. `dr_snode[dr_top]=b; dr_soldp[dr_top]=dr_p[b]; dr_soldr[dr_top]=dr_r[a]; dr_top++`
 *      — push three fields to undo stack before union
 *   3. `while (dr_top > cp) { dr_top--; restore ... }` — rollback to checkpoint
 *   4. `if (dr_r[a] < dr_r[b]) { swap a,b }` — union by rank (no compression)
 *   5. `return dr_top` — checkpoint is a simple integer (stack size)
 *
 * Test sequence on n=8 nodes:
 *   union(0,1)  → cp0
 *   union(2,3)  → cp1
 *   union(1,3)  → now {0,1,2,3} in one component
 *   connected(0,3) = 1                ← c1
 *   rollback(cp1) → undo union(1,3)   → {0,1} and {2,3} separate
 *   !connected(0,3) = 1               ← nc1
 *   rollback(cp0) → undo union(2,3)   → {0,1} and {2},{3} separate
 *   !connected(2,3) = 1               ← nc2
 *
 * n=8     = 0x08
 * c1=1    = 0x01
 * nc_sum=2= 0x02
 *
 * g_result = (n << 16) | (c1 << 8) | nc_sum = 0x080102
 */
#include <stdint.h>

volatile uint32_t g_result;

#define DR_N   8
#define DR_STK 32

static int dr_p[DR_N];
static int dr_r[DR_N];
static int dr_snode[DR_STK];
static int dr_soldp[DR_STK];
static int dr_soldr[DR_STK];
static int dr_top;

/* Find root WITHOUT path compression */
static int dr_find(int x)
{
    while (dr_p[x] != x) x = dr_p[x];
    return x;
}

static int dr_checkpoint(void) { return dr_top; }

/* Union by rank; push undo record before modifying */
static void dr_union(int a, int b)
{
    a = dr_find(a); b = dr_find(b);
    if (a == b) return;
    if (dr_r[a] < dr_r[b]) { int t = a; a = b; b = t; }
    dr_snode[dr_top] = b;
    dr_soldp[dr_top] = dr_p[b];
    dr_soldr[dr_top] = dr_r[a];
    dr_top++;
    dr_p[b] = a;
    if (dr_r[a] == dr_r[b]) dr_r[a]++;
}

/* Restore to checkpoint by popping the undo stack */
static void dr_rollback(int cp)
{
    while (dr_top > cp) {
        dr_top--;
        int b = dr_snode[dr_top];
        int a = dr_p[b];
        dr_p[b]  = dr_soldp[dr_top];
        dr_r[a]  = dr_soldr[dr_top];
    }
}

static int dr_conn(int a, int b) { return dr_find(a) == dr_find(b); }

void test_dsu_rollback(void)
{
    for (int i = 0; i < DR_N; i++) { dr_p[i] = i; dr_r[i] = 0; }
    dr_top = 0;

    dr_union(0, 1);
    int cp0 = dr_checkpoint();  /* after union(0,1) */

    dr_union(2, 3);
    int cp1 = dr_checkpoint();  /* after union(0,1) + union(2,3) */

    dr_union(1, 3);             /* merges {0,1} and {2,3} */

    int c1  = dr_conn(0, 3);       /* 1: connected through (0-1-3-2) */

    dr_rollback(cp1);              /* undo union(1,3) */
    int nc1 = !dr_conn(0, 3);      /* 1: {0,1} and {2,3} are separate */

    dr_rollback(cp0);              /* undo union(2,3) */
    int nc2 = !dr_conn(2, 3);      /* 1: 2 and 3 are now separate again */

    g_result = ((uint32_t)DR_N        << 16)
             | ((uint32_t)c1          << 8)
             | ((uint32_t)(nc1 + nc2) & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_dsu_rollback();
    for (;;);
}
