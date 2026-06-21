/* test_fibonacci_heap.c
 * Purpose   : Validate a Fibonacci heap for decrease-key and extract-min
 * Algorithm : Lazy insert links new trees to the root list in O(1).
 *             extract_min triggers consolidation (combine trees of same degree).
 *             decrease_key cuts a node if it violates the heap property and
 *             cascading-cuts its parent if it has already lost a child.
 * Input     : Insert keys 9,3,7,1,8,2,6,4  (n=8)
 *             decrease_key(9 → 0)
 *             extract 3 minimums → expect 0,1,2
 * n_ops     = 8  (0x08)
 * sum_min3  = 0+1+2 = 3  (0x03)
 * n_nodes   = 5  (0x05, remaining after 3 extractions)
 * g_result  = (n_ops << 16) | (sum_min3 << 8) | n_nodes = 0x080305
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define FH_MAX 16

typedef struct FHNode {
    int key;
    int degree;
    int mark;       /* 1 if lost a child since becoming non-root */
    int parent;     /* -1 = no parent */
    int child;      /* -1 = no children */
    int left, right;
} FHNode;

static FHNode fh_nodes[FH_MAX];
static int    fh_n;    /* number of nodes in heap */
static int    fh_min;  /* index of minimum node, -1 if empty */

/* ── Circular doubly-linked list helpers ──────────────────────────────────── */

static void fh_list_insert(int a, int b) {
    /* Insert node a after node b in b's root list */
    int br = fh_nodes[b].right;
    fh_nodes[a].left  = b;
    fh_nodes[a].right = br;
    fh_nodes[b].right = a;
    fh_nodes[br].left = a;
}

static void fh_list_remove(int a) {
    int l = fh_nodes[a].left;
    int r = fh_nodes[a].right;
    fh_nodes[l].right = r;
    fh_nodes[r].left  = l;
    fh_nodes[a].left  = a;
    fh_nodes[a].right = a;
}

/* ── Initialise a new node ────────────────────────────────────────────────── */

static int fh_new(int key) {
    int id = fh_n++;
    fh_nodes[id].key    = key;
    fh_nodes[id].degree = 0;
    fh_nodes[id].mark   = 0;
    fh_nodes[id].parent = -1;
    fh_nodes[id].child  = -1;
    fh_nodes[id].left   = id;
    fh_nodes[id].right  = id;
    return id;
}

/* ── Insert ───────────────────────────────────────────────────────────────── */

static void fh_insert(int key) {
    int nd = fh_new(key);
    if (fh_min == -1) {
        fh_min = nd;
    } else {
        fh_list_insert(nd, fh_min);
        if (key < fh_nodes[fh_min].key)
            fh_min = nd;
    }
}

/* ── Link tree y under x (x.key <= y.key) ───────────────────────────────── */

static void fh_link(int y, int x) {
    fh_list_remove(y);
    fh_nodes[y].parent = x;
    if (fh_nodes[x].child == -1) {
        fh_nodes[x].child  = y;
        fh_nodes[y].left   = y;
        fh_nodes[y].right  = y;
    } else {
        fh_list_insert(y, fh_nodes[x].child);
    }
    fh_nodes[x].degree++;
    fh_nodes[y].mark = 0;
}

/* ── Consolidate root list after extract_min ─────────────────────────────── */

static int fh_deg[FH_MAX]; /* degree table: fh_deg[d] = root with degree d */

static void fh_consolidate(void) {
    for (int i = 0; i < FH_MAX; i++) fh_deg[i] = -1;

    /* Collect all roots into a temporary array */
    int roots[FH_MAX];
    int nroots = 0;
    int cur = fh_min;
    do {
        roots[nroots++] = cur;
        cur = fh_nodes[cur].right;
    } while (cur != fh_min);

    for (int i = 0; i < nroots; i++) {
        int x = roots[i];
        int d = fh_nodes[x].degree;
        while (fh_deg[d] != -1) {
            int y = fh_deg[d];
            if (fh_nodes[x].key > fh_nodes[y].key) { int t = x; x = y; y = t; }
            fh_link(y, x);
            fh_deg[d] = -1;
            d++;
        }
        fh_deg[d] = x;
    }

    /* Rebuild root list and find new minimum */
    fh_min = -1;
    for (int i = 0; i < FH_MAX; i++) {
        int x = fh_deg[i];
        if (x == -1) continue;
        fh_nodes[x].left  = x;
        fh_nodes[x].right = x;
        if (fh_min == -1) {
            fh_min = x;
        } else {
            fh_list_insert(x, fh_min);
            if (fh_nodes[x].key < fh_nodes[fh_min].key)
                fh_min = x;
        }
    }
}

/* ── Extract minimum ──────────────────────────────────────────────────────── */

static int fh_extract_min(void) {
    int z = fh_min;
    if (z == -1) return -1;

    /* Add all children of z to root list */
    if (fh_nodes[z].child != -1) {
        int c = fh_nodes[z].child;
        do {
            int nc = fh_nodes[c].right;
            fh_nodes[c].parent = -1;
            fh_list_insert(c, fh_min);
            c = nc;
        } while (c != fh_nodes[z].child);
    }
    fh_list_remove(z);

    if (fh_nodes[z].right == z) {
        fh_min = -1;
    } else {
        fh_min = fh_nodes[z].right;
        fh_consolidate();
    }
    return fh_nodes[z].key;
}

/* ── Cut / cascading-cut / decrease-key ──────────────────────────────────── */

static void fh_cut(int x, int p) {
    /* Remove x from p's child list */
    if (fh_nodes[x].right == x) {
        fh_nodes[p].child = -1;
    } else {
        if (fh_nodes[p].child == x)
            fh_nodes[p].child = fh_nodes[x].right;
        fh_list_remove(x);
    }
    fh_nodes[p].degree--;
    fh_nodes[x].parent = -1;
    fh_nodes[x].mark   = 0;
    fh_list_insert(x, fh_min);
    if (fh_nodes[x].key < fh_nodes[fh_min].key)
        fh_min = x;
}

static void fh_cascading_cut(int y) {
    int p = fh_nodes[y].parent;
    if (p != -1) {
        if (!fh_nodes[y].mark) {
            fh_nodes[y].mark = 1;
        } else {
            fh_cut(y, p);
            fh_cascading_cut(p);
        }
    }
}

static void fh_decrease_key(int x, int new_key) {
    fh_nodes[x].key = new_key;
    int p = fh_nodes[x].parent;
    if (p != -1 && fh_nodes[x].key < fh_nodes[p].key) {
        fh_cut(x, p);
        fh_cascading_cut(p);
    }
    if (fh_nodes[x].key < fh_nodes[fh_min].key)
        fh_min = x;
}

void _start(void) {
    fh_n   = 0;
    fh_min = -1;

    /* Insert 8 keys */
    static const int keys[8] = { 9, 3, 7, 1, 8, 2, 6, 4 };
    int n_ops = 8;
    /* Insert all keys; track the node allocated for key==9 */
    fh_insert(keys[0]);          /* key=9 → node 0 */
    int id9 = 0;
    for (int i = 1; i < n_ops; i++)
        fh_insert(keys[i]);

    /* Decrease key 9 → 0 */
    fh_decrease_key(id9, 0);

    /* Extract 3 minimums: expect 0, 1, 2 */
    int sum_min3 = 0;
    for (int i = 0; i < 3; i++)
        sum_min3 += fh_extract_min();

    int n_nodes = fh_n - 3; /* 8 inserted, 3 extracted */

    g_result = ((uint32_t)n_ops     << 16)
             | ((uint32_t)sum_min3  <<  8)
             | ((uint32_t)n_nodes);
    while (1) {}
}
