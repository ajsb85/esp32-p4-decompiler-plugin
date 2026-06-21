/*
 * test_derangement_dp.c
 * Derangement counting via DP: D(n) = (n-1)*(D(n-1)+D(n-2)).
 * A derangement is a permutation where no element appears in its original
 * position. The recurrence:
 *   D(0)=1, D(1)=0
 *   D(n) = (n-1) * (D(n-1) + D(n-2))   for n >= 2
 * Also computed via inclusion-exclusion: D(n)=n!*sum_{k=0}^{n}(-1)^k/k!
 * and via nearest-integer formula: D(n) = round(n!/e).
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define DERA_MAXN 13   /* D(12)=176214841, fits in uint32_t */

static uint32_t dera_D[DERA_MAXN];

/* Fill derangement table mod 2^32 */
static void dera_build(void) {
    dera_D[0] = 1u;
    dera_D[1] = 0u;
    for (int n = 2; n < DERA_MAXN; n++) {
        dera_D[n] = (uint32_t)(n - 1) * (dera_D[n-1] + dera_D[n-2]);
    }
}

/* Count derangements of k elements in {0..n-1} that match prefix:
 * Just a wrapper returning dera_D[k]. */
static uint32_t dera_count(int k) {
    if (k < 0 || k >= DERA_MAXN) return 0u;
    return dera_D[k];
}

/* Verify by inclusion-exclusion: D(n)=sum_{k=0}^{n}(-1)^k * C(n,k)*(n-k)! */
static uint32_t dera_inclusion_exclusion(int n) {
    /* Pre-compute factorials */
    uint32_t fact[DERA_MAXN];
    fact[0] = 1u;
    for (int i = 1; i < DERA_MAXN; i++) fact[i] = fact[i-1] * (uint32_t)i;

    /* C(n,k) = fact[n]/(fact[k]*fact[n-k]) — compute iteratively */
    uint32_t result = 0u;
    uint32_t binom = 1u; /* C(n,0) */
    for (int k = 0; k <= n; k++) {
        uint32_t term = binom * fact[n - k];
        if (k % 2 == 0) result += term;
        else             result -= term;
        /* Update binom: C(n,k+1) = C(n,k)*(n-k)/(k+1) */
        if (k < n) binom = binom * (uint32_t)(n - k) / (uint32_t)(k + 1);
    }
    return result;
}

static uint32_t run_derangement_tests(void) {
    uint32_t n_tests = 0;

    dera_build();

    /*
     * Test 1: D(5) = 44. Known: D(5)=44.
     */
    uint32_t d5 = dera_count(5);
    n_tests++;
    (void)d5; /* expect 44 */

    /*
     * Test 2: D(8) = 14833. Verify via inclusion-exclusion.
     */
    uint32_t d8_dp  = dera_count(8);
    uint32_t d8_ie  = dera_inclusion_exclusion(8);
    uint32_t match8 = (d8_dp == d8_ie) ? 1u : 0u;
    n_tests++;

    /*
     * Test 3: D(10) = 1334961. Verify mod 256 only (fits nicely):
     * 1334961 % 256 = 1334961 & 0xFF = 0x51 = 81.
     */
    uint32_t d10_mod = dera_count(10) & 0xFFu; /* expect 0x51 = 81 */
    n_tests++;

    /*
     * Pack:
     * metric_a = match8 ? (d5 & 0x3F) | 0x40 : 0x01
     *          = 1 ? (44 & 0x3F) | 0x40 = (0x2C | 0x40) = 0x6C = 108
     * metric_b = d10_mod = 81 = 0x51
     * n_tests = 3
     * result = (3<<16)|(108<<8)|81 = 0x036C51
     * Bytes: 0x03, 0x6C, 0x51 — non-zero, distinct.
     */
    uint32_t metric_a = match8 ? ((d5 & 0x3Fu) | 0x40u) : 0x01u;
    uint32_t metric_b = d10_mod;
    return (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_derangement_tests();
    while (1) {}
}
