/*
 * test_mex_grundy_game.c
 * Grundy values (nimbers) via MEX (Minimum EXcludant) for combinatorial games.
 *
 * MEX of a set S = smallest non-negative integer not in S.
 * Grundy value G(pos) = mex({ G(next) : next reachable from pos }).
 *
 * Games implemented:
 * 1. Subtraction game S={1,2,3}: G(n) = n % 4.
 *    G(0)=0, G(1)=1, G(2)=2, G(3)=3, G(4)=0, ...
 *
 * 2. Turning Turtles / Nim single pile: G(n) = n.
 *    Standard 1-pile Nim: from pile n, can remove 1..n stones.
 *    G(0)=0, G(n)=mex(G(0),...,G(n-1))=n.
 *
 * 3. Green Hackenbush on a path of n edges: G(n) = n.
 *    (Same as nim — used to verify mex computation.)
 *
 * Tests:
 *   1. Subtraction game G values for n=0..7: verify G(4)=0, G(7)=3.
 *   2. Nim-pile G values for n=0..6: verify G(5)=5.
 *   3. Multi-game XOR: two piles [3,5] => Grundy XOR = 3^5 = 6 => first player wins (!=0).
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MEX_MAXN 16u

/* Compute mex of g[0..top-1] restricted to small values (0..top) */
static uint32_t compute_mex(const uint32_t *reachable, uint32_t cnt) {
    /* Mark which values are present (0..MEX_MAXN) */
    uint8_t present[MEX_MAXN + 1u];
    for (uint32_t i = 0u; i <= MEX_MAXN; i++) present[i] = 0u;
    for (uint32_t i = 0u; i < cnt; i++) {
        if (reachable[i] <= MEX_MAXN) present[reachable[i]] = 1u;
    }
    for (uint32_t m = 0u; m <= MEX_MAXN; m++) {
        if (!present[m]) return m;
    }
    return MEX_MAXN + 1u; /* unreachable for our sizes */
}

/* Subtraction game with S = {1,2,3}: from position n, can move to n-1,n-2,n-3 */
static void subtraction_grundy(uint32_t *g, uint32_t maxn) {
    g[0] = 0u;
    for (uint32_t n = 1u; n <= maxn; n++) {
        uint32_t reachable[3];
        uint32_t cnt = 0u;
        if (n >= 1u) reachable[cnt++] = g[n - 1u];
        if (n >= 2u) reachable[cnt++] = g[n - 2u];
        if (n >= 3u) reachable[cnt++] = g[n - 3u];
        g[n] = compute_mex(reachable, cnt);
    }
}

/* Standard single-pile Nim: from pile n, remove 1..n. G(n)=n. */
static void nim_pile_grundy(uint32_t *g, uint32_t maxn) {
    g[0] = 0u;
    for (uint32_t n = 1u; n <= maxn; n++) {
        uint32_t reachable[MEX_MAXN];
        uint32_t cnt = 0u;
        /* Can move to any pile size 0..n-1 */
        for (uint32_t k = 0u; k < n && k < MEX_MAXN; k++) {
            reachable[cnt++] = g[k];
        }
        g[n] = compute_mex(reachable, cnt);
    }
}

static uint32_t run_mex_grundy_tests(void) {
    uint32_t n_tests = 0u;

    /*
     * Test 1: Subtraction game G(n) for n=0..7.
     * Expected: 0,1,2,3,0,1,2,3 (period 4).
     */
    uint32_t sub_g[8];
    subtraction_grundy(sub_g, 7u);
    uint32_t g4 = sub_g[4];  /* expect 0 */
    uint32_t g7 = sub_g[7];  /* expect 3 */
    n_tests++;

    /*
     * Test 2: Nim-pile G values for n=0..6.
     * Expected: G(n) = n.
     */
    uint32_t nim_g[7];
    nim_pile_grundy(nim_g, 6u);
    uint32_t g5 = nim_g[5];  /* expect 5 */
    uint32_t g6 = nim_g[6];  /* expect 6 */
    n_tests++;

    /*
     * Test 3: Multi-game XOR of two Nim piles [3, 5].
     * Grundy XOR = G(3) XOR G(5) = 3 XOR 5 = 6 => first player wins.
     */
    uint32_t multi_xor = nim_g[3] ^ nim_g[5]; /* 3^5=6 */
    uint32_t first_wins = (multi_xor != 0u) ? 1u : 0u;
    n_tests++;

    /*
     * Pack result:
     * n_tests = 3 = 0x03
     * metric_a = (g4 << 6) | (g7 << 4) | (g5 & 0xF)
     *          = (0<<6)|(3<<4)|(5&0xF) = 0|48|5 = 53 = 0x35
     * metric_b = (g6 << 4) | (multi_xor & 0xF) | (first_wins << 7)
     *          = (6<<4)|(6&0xF)|(1<<7) = 96|6|128 = 230 = 0xE6
     * Result = (0x03<<16)|(0x35<<8)|0xE6 = 0x0335E6
     * Bytes: 0x03, 0x35, 0xE6 — non-zero, distinct. Good.
     */
    uint32_t metric_a = (g4 << 6u) | (g7 << 4u) | (g5 & 0xFu);
    uint32_t metric_b = (g6 << 4u) | (multi_xor & 0xFu) | (first_wins << 7u);
    return (n_tests << 16u) | (metric_a << 8u) | metric_b;
}

void _start(void) {
    g_result = run_mex_grundy_tests();
    while (1) {}
}
