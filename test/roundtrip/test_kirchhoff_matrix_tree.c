/* Kirchhoff's Matrix-Tree Theorem (Kirchhoff / Laplacian determinant)
 * Builds the Laplacian matrix of a graph, computes its (n-1)x(n-1)
 * cofactor via Gaussian elimination over integers, and returns the
 * number of spanning trees.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define KMT_MAXN  6

/* Laplacian matrix (integer) */
static int32_t kmt_L[KMT_MAXN][KMT_MAXN];
/* Working copy for Gaussian elimination */
static int32_t kmt_M[KMT_MAXN][KMT_MAXN];

static void kmt_init(int32_t n) {
    for (int32_t i = 0; i < n; i++)
        for (int32_t j = 0; j < n; j++)
            kmt_L[i][j] = 0;
}

/* Add undirected edge u-v with weight w */
static void kmt_add_edge(int32_t u, int32_t v, int32_t w) {
    kmt_L[u][u] += w;
    kmt_L[v][v] += w;
    kmt_L[u][v] -= w;
    kmt_L[v][u] -= w;
}

/* Bareiss integer-preserving Gaussian elimination for (n-1)x(n-1) cofactor.
 * Returns the determinant of kmt_M (size m x m). */
static int32_t kmt_det(int32_t m) {
    int32_t sign = 1;
    int32_t prev = 1;
    for (int32_t col = 0; col < m; col++) {
        /* Find pivot */
        int32_t pivot = -1;
        for (int32_t row = col; row < m; row++) {
            if (kmt_M[row][col] != 0) { pivot = row; break; }
        }
        if (pivot < 0) return 0; /* singular */
        if (pivot != col) {
            for (int32_t j = 0; j < m; j++) {
                int32_t tmp = kmt_M[col][j];
                kmt_M[col][j] = kmt_M[pivot][j];
                kmt_M[pivot][j] = tmp;
            }
            sign = -sign;
        }
        for (int32_t row = col + 1; row < m; row++) {
            for (int32_t j = col + 1; j < m; j++) {
                /* Bareiss: M[row][j] = (M[col][col]*M[row][j] - M[row][col]*M[col][j]) / prev */
                int32_t num = kmt_M[col][col] * kmt_M[row][j]
                            - kmt_M[row][col] * kmt_M[col][j];
                kmt_M[row][j] = num / prev;
            }
            kmt_M[row][col] = 0;
        }
        prev = kmt_M[col][col];
    }
    int32_t det = kmt_M[m-1][m-1];
    return sign * det;
}

/* Compute number of spanning trees of n-node graph via Kirchhoff's theorem */
static int32_t kmt_spanning_trees(int32_t n) {
    if (n <= 1) return 1;
    /* Copy (n-1)x(n-1) submatrix (delete row 0, col 0) */
    int32_t m = n - 1;
    for (int32_t i = 0; i < m; i++)
        for (int32_t j = 0; j < m; j++)
            kmt_M[i][j] = kmt_L[i+1][j+1];
    return kmt_det(m);
}

static void test_kirchhoff_matrix_tree(void) {
    int32_t n_tests  = 0;
    int32_t n_passed = 0;
    int32_t total_trees = 0;

    /* Test 1: Complete graph K4 has 4^(4-2) = 16 spanning trees */
    {
        kmt_init(4);
        kmt_add_edge(0,1,1); kmt_add_edge(0,2,1); kmt_add_edge(0,3,1);
        kmt_add_edge(1,2,1); kmt_add_edge(1,3,1); kmt_add_edge(2,3,1);
        int32_t t = kmt_spanning_trees(4);
        n_tests++;
        if (t == 16) n_passed++;
        total_trees += t;
    }

    /* Test 2: Path graph P3 (0-1-2) has exactly 1 spanning tree */
    {
        kmt_init(3);
        kmt_add_edge(0,1,1); kmt_add_edge(1,2,1);
        int32_t t = kmt_spanning_trees(3);
        n_tests++;
        if (t == 1) n_passed++;
        total_trees += t;
    }

    /* Test 3: K3 (triangle) has 3 spanning trees */
    {
        kmt_init(3);
        kmt_add_edge(0,1,1); kmt_add_edge(1,2,1); kmt_add_edge(0,2,1);
        int32_t t = kmt_spanning_trees(3);
        n_tests++;
        if (t == 3) n_passed++;
        total_trees += t;
    }

    /* n_tests=3=0x03, n_passed=3=0x03 -> collision with n_tests in byte positions */
    /* total_trees = 16+1+3 = 20 = 0x14 -- distinct from 0x03 */
    uint32_t metric_a = (uint32_t)(n_passed    & 0xFF); /* 0x03 */
    uint32_t metric_b = (uint32_t)(total_trees & 0xFF); /* 0x14 */
    g_result = ((uint32_t)n_tests << 16) | (metric_a << 8) | metric_b;
    /* => 0x00030314 — n_tests=3, metric_a=3, metric_b=20; all non-zero; 3!=20 */
}

void _start(void) {
    test_kirchhoff_matrix_tree();
    while (1) {}
}
