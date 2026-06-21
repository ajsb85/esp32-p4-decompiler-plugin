/*
 * test_fast_fourier_mod.c
 * Number-theoretic transform (NTT) modular-arithmetic polynomial
 * multiplication over a prime field.
 * Uses prime p=7681 = 15*2^9+1 (NTT-friendly, primitive root g=17),
 * max NTT length 2^9=512.  All intermediate products fit in uint32_t
 * (max product < 7681^2 < 2^26), so no 64-bit division is needed.
 * Implements iterative Cooley-Tukey NTT for mod-prime polynomial multiply.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FFM_MOD  7681u   /* prime, NTT-friendly: 15*2^9+1 */
#define FFM_G    17u     /* primitive root mod FFM_MOD */
#define FFM_MAXN 16      /* max NTT length (power of 2, <= 512) */

typedef uint32_t u32;

/* Modular multiply without 64-bit: a,b < FFM_MOD < 2^13, so a*b < 2^26 */
static u32 ffm_mulmod(u32 a, u32 b) {
    return (a * b) % FFM_MOD;
}

static u32 ffm_pow(u32 base, u32 exp) {
    u32 result = 1;
    base %= FFM_MOD;
    while (exp > 0) {
        if (exp & 1u) result = ffm_mulmod(result, base);
        base = ffm_mulmod(base, base);
        exp >>= 1;
    }
    return result;
}

static u32 ffm_inv(u32 a) {
    return ffm_pow(a, FFM_MOD - 2u);
}

/* Bit-reversal permutation */
static void ffm_bit_rev(u32 *a, int n) {
    for (int i = 1, j = 0; i < n; i++) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) { u32 t = a[i]; a[i] = a[j]; a[j] = t; }
    }
}

/* Iterative NTT. invert=0: forward, invert=1: inverse */
static void ffm_ntt(u32 *a, int n, int invert) {
    ffm_bit_rev(a, n);
    for (int len = 2; len <= n; len <<= 1) {
        u32 w = invert
            ? ffm_pow(ffm_inv(FFM_G), (FFM_MOD - 1u) / (u32)len)
            : ffm_pow(FFM_G,          (FFM_MOD - 1u) / (u32)len);
        for (int i = 0; i < n; i += len) {
            u32 wn = 1;
            for (int j = 0; j < len / 2; j++) {
                u32 u = a[i + j];
                u32 v = ffm_mulmod(a[i + j + len/2], wn);
                a[i + j]          = (u + v) % FFM_MOD;
                a[i + j + len/2]  = (u + FFM_MOD - v) % FFM_MOD;
                wn = ffm_mulmod(wn, w);
            }
        }
    }
    if (invert) {
        u32 n_inv = ffm_inv((u32)n);
        for (int i = 0; i < n; i++)
            a[i] = ffm_mulmod(a[i], n_inv);
    }
}

/* Working buffers for NTT multiply */
static u32 ffm_fa[FFM_MAXN], ffm_fb[FFM_MAXN], ffm_fc[FFM_MAXN];

static void ffm_multiply(const u32 *fa, int la, const u32 *fb, int lb) {
    int n = 1;
    while (n < la + lb) n <<= 1;
    for (int i = 0; i < n; i++) {
        ffm_fa[i] = (i < la) ? fa[i] % FFM_MOD : 0u;
        ffm_fb[i] = (i < lb) ? fb[i] % FFM_MOD : 0u;
    }
    ffm_ntt(ffm_fa, n, 0);
    ffm_ntt(ffm_fb, n, 0);
    for (int i = 0; i < n; i++)
        ffm_fc[i] = ffm_mulmod(ffm_fa[i], ffm_fb[i]);
    ffm_ntt(ffm_fc, n, 1);
}

static uint32_t run_ffm_tests(void) {
    /*
     * Test 1: Multiply (1 + x) * (1 + x) = 1 + 2x + x^2
     * a=[1,1], b=[1,1], result=[1,2,1] (all < FFM_MOD so no reduction)
     */
    u32 a1[2] = {1, 1};
    u32 b1[2] = {1, 1};
    ffm_multiply(a1, 2, b1, 2);
    u32 c1_1 = ffm_fc[1]; /* 2 */
    int ok1 = (ffm_fc[0] == 1u && c1_1 == 2u && ffm_fc[2] == 1u);

    /*
     * Test 2: Multiply (1 + 2x + 3x^2) * (4 + 5x)
     *   = 4 + 13x + 22x^2 + 15x^3
     */
    u32 a2[3] = {1, 2, 3};
    u32 b2[2] = {4, 5};
    ffm_multiply(a2, 3, b2, 2);
    int ok2 = (ffm_fc[0] == 4u && ffm_fc[1] == 13u &&
               ffm_fc[2] == 22u && ffm_fc[3] == 15u);

    /*
     * Test 3: Scalar convolution. (7) * (5) = 35 mod 7681 = 35.
     */
    u32 a3[1] = {7};
    u32 b3[1] = {5};
    ffm_multiply(a3, 1, b3, 1);
    int ok3 = (ffm_fc[0] == 35u);

    /*
     * Pack: n_tests=3, metric_a = ok1|(ok2<<1)|(ok3<<2) = 0x07,
     * metric_b = c1_1 * 0x11 = 2*17 = 34 = 0x22.
     * Bytes: 0x03, 0x07, 0x22 — all non-zero, distinct.
     */
    uint32_t metric_a = (uint32_t)((ok1 & 1) | ((ok2 & 1) << 1) | ((ok3 & 1) << 2));
    uint32_t metric_b = (uint32_t)(c1_1 * 0x11u); /* 2*17=34=0x22 */
    return (3u << 16) | (metric_a << 8) | (metric_b & 0xFF);
}

void _start(void) {
    g_result = run_ffm_tests();
    while (1) {}
}
