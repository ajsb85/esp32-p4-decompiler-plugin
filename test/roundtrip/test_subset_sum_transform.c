/* Subset Sum (OR/AND/XOR) Transform — Sum over Subsets (SOS) DP
 * Computes the sum-over-subsets (Zeta transform), Mobius inversion,
 * and XOR convolution via Walsh-Hadamard Transform (WHT).
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SST_LOG  4          /* log2 of transform size */
#define SST_N    (1 << SST_LOG)   /* 16 */

static int32_t sst_a[SST_N];  /* input array */
static int32_t sst_f[SST_N];  /* transform output */

/* OR (Zeta) transform: f[mask] = sum of a[sub] for all sub ⊆ mask */
static void sst_or_transform(void) {
    for (int32_t i = 0; i < SST_N; i++) sst_f[i] = sst_a[i];
    for (int32_t i = 0; i < SST_LOG; i++) {
        for (int32_t mask = 0; mask < SST_N; mask++) {
            if (mask & (1 << i)) {
                sst_f[mask] += sst_f[mask ^ (1 << i)];
            }
        }
    }
}

/* Mobius inversion (inverse Zeta/OR): recover a from f */
static void sst_mobius_invert(void) {
    for (int32_t i = 0; i < SST_LOG; i++) {
        for (int32_t mask = 0; mask < SST_N; mask++) {
            if (mask & (1 << i)) {
                sst_f[mask] -= sst_f[mask ^ (1 << i)];
            }
        }
    }
}

/* AND transform: f[mask] = sum of a[sup] for all sup ⊇ mask */
static void sst_and_transform(void) {
    for (int32_t i = 0; i < SST_N; i++) sst_f[i] = sst_a[i];
    for (int32_t i = 0; i < SST_LOG; i++) {
        for (int32_t mask = 0; mask < SST_N; mask++) {
            if (!(mask & (1 << i))) {
                sst_f[mask] += sst_f[mask | (1 << i)];
            }
        }
    }
}

/* XOR (Walsh-Hadamard) transform in-place on sst_f */
static void sst_wht(int32_t inv) {
    for (int32_t len = 1; len < SST_N; len <<= 1) {
        for (int32_t i = 0; i < SST_N; i += len << 1) {
            for (int32_t j = 0; j < len; j++) {
                int32_t u = sst_f[i + j];
                int32_t v = sst_f[i + j + len];
                sst_f[i + j]       = u + v;
                sst_f[i + j + len] = u - v;
            }
        }
    }
    if (inv) {
        for (int32_t i = 0; i < SST_N; i++) sst_f[i] /= SST_N;
    }
}

static void test_subset_sum_transform(void) {
    int32_t n_tests  = 0;
    int32_t n_passed = 0;
    int32_t checksum = 0;

    /* Test 1: OR transform correctness — a[i]=1 for all i, f[SST_N-1] should equal SST_N */
    {
        for (int32_t i = 0; i < SST_N; i++) sst_a[i] = 1;
        sst_or_transform();
        n_tests++;
        /* f[all-ones mask] = count of all subsets = 2^SST_LOG = SST_N */
        if (sst_f[SST_N - 1] == SST_N) n_passed++;
        checksum += sst_f[0]; /* f[0] = a[0] = 1 */
    }

    /* Test 2: Mobius inversion recovers original a */
    {
        /* sst_f still has OR transform result, invert it */
        sst_mobius_invert();
        n_tests++;
        int32_t ok = 1;
        for (int32_t i = 0; i < SST_N; i++) {
            if (sst_f[i] != 1) { ok = 0; break; }
        }
        if (ok) n_passed++;
    }

    /* Test 3: AND transform — a[i]=1, f[0] should equal SST_N */
    {
        for (int32_t i = 0; i < SST_N; i++) sst_a[i] = 1;
        sst_and_transform();
        n_tests++;
        if (sst_f[0] == SST_N) n_passed++;
        checksum += sst_f[SST_N - 1]; /* f[1111] = a[1111] = 1 */
    }

    /* Test 4: XOR convolution identity — convolve {1,0,0,...} with any array = that array */
    {
        /* Set a = indicator of element 0 only: a[0]=1, rest 0 */
        for (int32_t i = 0; i < SST_N; i++) sst_f[i] = (i == 0) ? 1 : 0;
        /* Convolve with itself: WHT, pointwise square, iWHT */
        sst_wht(0);
        for (int32_t i = 0; i < SST_N; i++) sst_f[i] *= sst_f[i];
        sst_wht(1);
        /* Result should have sst_f[0]=1, rest 0 (1 XOR-convolved with 1 = delta at 0) */
        n_tests++;
        if (sst_f[0] == 1) {
            int32_t ok = 1;
            for (int32_t i = 1; i < SST_N; i++) {
                if (sst_f[i] != 0) { ok = 0; break; }
            }
            if (ok) n_passed++;
        }
    }

    /* n_tests=4=0x04, n_passed=4=0x04 -> collision -> use checksum low byte */
    uint32_t metric_a = (uint32_t)(n_passed & 0xFF); /* 0x04 */
    uint32_t metric_b = (uint32_t)(checksum & 0xFF); /* 1+1=2 -> 0x02 */
    g_result = ((uint32_t)n_tests << 16) | (metric_a << 8) | metric_b;
    /* => 0x00040402 — n_tests=4, metric_a=4, metric_b=2; all non-zero, metric_b distinct */
}

void _start(void) {
    test_subset_sum_transform();
    while (1) {}
}
