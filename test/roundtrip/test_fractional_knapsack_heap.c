/*
 * test_fractional_knapsack_heap.c
 * Fractional knapsack solved with a max-heap (priority queue on value/weight
 * ratio).  Items are heapified by ratio; greedily extracted until capacity
 * is consumed.  Result is scaled integer (ratio * 100 truncated) to keep
 * everything in 32-bit integer arithmetic.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FKH_MAXN  16

typedef struct {
    uint32_t value;   /* scaled: actual_value * 100 */
    uint32_t weight;  /* in units */
    uint32_t ratio;   /* value / weight (integer division) */
} FKItem;

static FKItem fkh_heap[FKH_MAXN];
static int    fkh_size;

static void fkh_swap(int a, int b) {
    FKItem tmp = fkh_heap[a];
    fkh_heap[a] = fkh_heap[b];
    fkh_heap[b] = tmp;
}

/* Max-heap by ratio */
static void fkh_push(FKItem it) {
    fkh_heap[fkh_size] = it;
    int i = fkh_size++;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (fkh_heap[p].ratio >= fkh_heap[i].ratio) break;
        fkh_swap(p, i);
        i = p;
    }
}

static FKItem fkh_pop(void) {
    FKItem top = fkh_heap[0];
    fkh_heap[0] = fkh_heap[--fkh_size];
    int i = 0;
    while (1) {
        int l = 2*i+1, r = 2*i+2, largest = i;
        if (l < fkh_size && fkh_heap[l].ratio > fkh_heap[largest].ratio) largest = l;
        if (r < fkh_size && fkh_heap[r].ratio > fkh_heap[largest].ratio) largest = r;
        if (largest == i) break;
        fkh_swap(i, largest);
        i = largest;
    }
    return top;
}

/*
 * Greedy fractional knapsack.
 * Returns total value (scaled *100) * 100 / capacity to normalise;
 * but we keep it simple: return accumulated value (scaled by 100) capped at
 * capacity * max_ratio for 32-bit safety.
 *
 * Returns total value scaled (value_units * 100) for capacity.
 */
static uint32_t fkh_solve(FKItem *items, int n, uint32_t capacity) {
    fkh_size = 0;
    for (int i = 0; i < n; i++) {
        items[i].ratio = items[i].value / items[i].weight;
        fkh_push(items[i]);
    }

    uint32_t total_value = 0; /* value * 100 */
    uint32_t remaining = capacity;

    while (fkh_size > 0 && remaining > 0) {
        FKItem best = fkh_pop();
        if (best.weight <= remaining) {
            total_value += best.value;
            remaining   -= best.weight;
        } else {
            /* Take fraction: value * remaining / weight */
            total_value += best.value * remaining / best.weight;
            remaining = 0;
        }
    }
    return total_value;
}

static uint32_t run_fkh_tests(void) {
    /*
     * Test 1: 4 items, capacity = 50
     * item0: v=6000(=60.00), w=10  ratio=600
     * item1: v=10000(=100.00),w=20 ratio=500
     * item2: v=12000(=120.00),w=30 ratio=400
     * item3: v=5000(=50.00), w=50  ratio=100
     * Greedy order: item0(w=10,full), item1(w=20,full), item2(w=30,take 20/30)
     * total = 6000 + 10000 + 12000*20/30 = 16000 + 8000 = 24000
     */
    FKItem items1[4] = {
        {6000, 10, 0},
        {10000,20, 0},
        {12000,30, 0},
        {5000, 50, 0},
    };
    uint32_t v1 = fkh_solve(items1, 4, 50); /* expect 24000 */

    /*
     * Test 2: 3 items, capacity = 15
     * item0: v=500, w=5   ratio=100
     * item1: v=1000,w=10  ratio=100
     * item2: v=300, w=3   ratio=100  (all equal ratio)
     * Take greedily: all weight=18 > 15, take items in heap order (any subset)
     * At ratio=100 all are equivalent. Total for 15 units = 100*15 = 1500.
     */
    FKItem items2[3] = {
        {500, 5, 0},
        {1000,10,0},
        {300, 3, 0},
    };
    uint32_t v2 = fkh_solve(items2, 3, 15); /* expect 1500 */

    /*
     * Test 3: single item, partial take
     * item: v=1000, w=100, capacity=40
     * take 40/100 fraction: value = 1000*40/100 = 400
     */
    FKItem items3[1] = { {1000, 100, 0} };
    uint32_t v3 = fkh_solve(items3, 1, 40); /* expect 400 */

    /*
     * Pack: n_tests=3
     * metric_a = (v1/1000) & 0xFF = 24 = 0x18
     * metric_b = (v2/100)  & 0xFF = 15 = 0x0F
     * result = (3<<16)|(0x18<<8)|0x0F = 0x03180F
     * Bytes 0x03, 0x18, 0x0F all non-zero and distinct.
     */
    uint32_t metric_a = (v1 / 1000u) & 0xFFu; /* 24 = 0x18 */
    uint32_t metric_b = (v2 / 100u)  & 0xFFu; /* 15 = 0x0F */
    (void)v3;
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_fkh_tests();
    while (1) {}
}
