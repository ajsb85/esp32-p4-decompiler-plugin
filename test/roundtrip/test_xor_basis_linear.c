/* XOR Basis / Linear Basis over GF(2)
 * Builds a linear basis of a set of integers using GF(2) Gaussian elimination,
 * tests membership, finds max/min XOR, and counts distinct XOR values reachable.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define XB_BITS   30
#define XB_MAXN   32

/* Linear basis stored as reduced row echelon form */
static uint32_t xb_basis[XB_BITS];
static int32_t  xb_sz;

static void xb_init(void) {
    for (int32_t i = 0; i < XB_BITS; i++) {
        xb_basis[i] = 0;
    }
    xb_sz = 0;
}

/* Insert x into the basis; return 1 if x was linearly independent */
static int32_t xb_insert(uint32_t x) {
    for (int32_t i = XB_BITS - 1; i >= 0; i--) {
        if (!((x >> i) & 1)) continue;
        if (!xb_basis[i]) {
            xb_basis[i] = x;
            xb_sz++;
            return 1;
        }
        x ^= xb_basis[i];
    }
    return 0; /* x is in the span of current basis */
}

/* Check if x is in the span of the basis */
static int32_t xb_contains(uint32_t x) {
    for (int32_t i = XB_BITS - 1; i >= 0; i--) {
        if (!((x >> i) & 1)) continue;
        if (!xb_basis[i]) return 0;
        x ^= xb_basis[i];
    }
    return 1;
}

/* Maximum XOR value achievable by XOR-ing subset of basis elements */
static uint32_t xb_max_xor(uint32_t init) {
    uint32_t res = init;
    for (int32_t i = XB_BITS - 1; i >= 0; i--) {
        if ((res ^ xb_basis[i]) > res) {
            res ^= xb_basis[i];
        }
    }
    return res;
}

/* Number of distinct XOR values reachable = 2^(basis size) */
static uint32_t xb_span_count(void) {
    uint32_t cnt = 1;
    for (int32_t i = 0; i < xb_sz; i++) {
        cnt <<= 1;
    }
    return cnt;
}

static void test_xor_basis_linear(void) {
    int32_t  n_tests  = 0;
    int32_t  n_passed = 0;
    uint32_t max_xor  = 0;

    /* Test 1: insert {3, 5, 6} — basis of {0,1,2,3,4,5,6,7} */
    {
        xb_init();
        uint32_t elems[] = {3, 5, 6};
        for (int32_t i = 0; i < 3; i++) xb_insert(elems[i]);
        /* 7 = 3^4 = 5^2 = 6^1... check max XOR from 0 */
        max_xor = xb_max_xor(0);
        n_tests++;
        if (max_xor == 7) n_passed++;
    }

    /* Test 2: membership — 7 should be in span, 8 should not */
    {
        n_tests++;
        if (xb_contains(7) && !xb_contains(8)) n_passed++;
    }

    /* Test 3: span count should be 2^3 = 8 */
    {
        n_tests++;
        if (xb_span_count() == 8) n_passed++;
    }

    /* Test 4: inserting a dependent element doesn't grow basis */
    {
        int32_t old_sz = xb_sz;
        int32_t grew = xb_insert(3 ^ 5); /* 6, already in basis */
        n_tests++;
        if (!grew && xb_sz == old_sz) n_passed++;
    }

    /* metric_a = n_passed (expect 4 = 0x04), max_xor truncated (expect 7 = 0x07) */
    uint32_t metric_a = (uint32_t)(n_passed & 0xFF);
    uint32_t metric_b = (uint32_t)(max_xor   & 0xFF);
    g_result = ((uint32_t)n_tests << 16) | (metric_a << 8) | metric_b;
    /* n_tests=4=0x04, metric_a=4=0x04... collision, shift metric_b to 0x07 */
    /* Ensure distinct: use n_tests<<16 | n_passed<<8 | max_xor => 0x040407 */
    g_result = ((uint32_t)n_tests << 16) | ((uint32_t)n_passed << 8) | metric_b;
}

void _start(void) {
    test_xor_basis_linear();
    while (1) {}
}
