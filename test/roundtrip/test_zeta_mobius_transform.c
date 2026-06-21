/*
 * test_zeta_mobius_transform.c
 * Zeta transform (sum over subsets) and Mobius inversion (inclusion-exclusion
 * inverse) over the boolean lattice (subsets of {0..n-1}).
 * Operates on arrays indexed by bitmasks.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define ZM_MAXN 5          /* up to 2^5 = 32 elements */
#define ZM_SZ   (1 << ZM_MAXN)

/*
 * Subset-sum zeta transform (SOS/OR convolution forward pass):
 *   f'[mask] = sum of f[sub] for all sub ⊆ mask
 * In-place, O(n * 2^n).
 */
static void zeta_transform(int32_t *a, int n) {
    for (int i = 0; i < n; i++) {
        for (int mask = 0; mask < (1 << n); mask++) {
            if (mask & (1 << i))
                a[mask] += a[mask ^ (1 << i)];
        }
    }
}

/*
 * Mobius inversion (inverse of zeta over subsets):
 *   g[mask] = sum_{sub ⊆ mask} (-1)^{|mask\sub|} f'[sub]
 * Recovers f from f'.
 */
static void mobius_transform(int32_t *a, int n) {
    for (int i = 0; i < n; i++) {
        for (int mask = 0; mask < (1 << n); mask++) {
            if (mask & (1 << i))
                a[mask] -= a[mask ^ (1 << i)];
        }
    }
}

/*
 * Superset-sum zeta (AND-convolution direction):
 *   f'[mask] = sum of f[sup] for all sup ⊇ mask
 */
static void zeta_superset(int32_t *a, int n) {
    for (int i = 0; i < n; i++) {
        for (int mask = (1 << n) - 1; mask >= 0; mask--) {
            if (!(mask & (1 << i)))
                a[mask] += a[mask | (1 << i)];
        }
    }
}

static uint32_t run_zeta_mobius_tests(void) {
    /*
     * Test 1: zeta then mobius recovers original on n=3 (8 elements).
     * Original: f[i] = i+1  (i in 0..7)
     * After zeta->mobius we must get back f[i] = i+1.
     * Verify f[7] == 8 after round-trip.
     */
    static int32_t a1[8];
    for (int i = 0; i < 8; i++) a1[i] = (int32_t)(i + 1);
    zeta_transform(a1, 3);
    int32_t zeta_all = a1[7]; /* should be sum 1..8 = 36 */
    mobius_transform(a1, 3);
    int32_t recover7 = a1[7]; /* should be 8 */
    (void)zeta_all;

    /*
     * Test 2: zeta of unit vector e_{0b101=5} on n=3.
     * f[5]=1, others 0. f'[mask] = 1 iff 5 ⊆ mask i.e. mask has bits 0 and 2.
     * f'[7] (=0b111) should be 1, f'[5]=1, f'[3]=0.
     */
    static int32_t a2[8];
    for (int i = 0; i < 8; i++) a2[i] = (i == 5) ? 1 : 0;
    zeta_transform(a2, 3);
    int32_t z2_7 = a2[7]; /* expect 1 */
    int32_t z2_3 = a2[3]; /* expect 0 */
    (void)z2_3;

    /*
     * Test 3: superset zeta of e_{0b010=2} on n=3.
     * f[2]=1 others 0. f'[mask] = 1 iff mask ⊆ 2, i.e. mask in {0, 2}.
     * f'[0] should be 1.
     */
    static int32_t a3[8];
    for (int i = 0; i < 8; i++) a3[i] = (i == 2) ? 1 : 0;
    zeta_superset(a3, 3);
    int32_t zs3_0 = a3[0]; /* expect 1 */
    (void)zs3_0;

    /*
     * Pack: n_tests=3, metric_a=recover7 (8=0x08), metric_b=(z2_7+(zs3_0<<1)) ...
     * recover7=8=0x08, z2_7=1=0x01 — (3<<16)|(0x08<<8)|0x01 = 0x030801
     * Bytes 0x03, 0x08, 0x01 — all non-zero and distinct.
     */
    uint32_t metric_a = (uint32_t)(recover7 & 0xFF); /* 8 = 0x08 */
    uint32_t metric_b = (uint32_t)(z2_7 & 0xFF);     /* 1 = 0x01 */
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_zeta_mobius_tests();
    while (1) {}
}
