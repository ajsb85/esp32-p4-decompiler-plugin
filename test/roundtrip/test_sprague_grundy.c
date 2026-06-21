/* test_sprague_grundy.c
 * Purpose   : Validate Sprague-Grundy theorem for combinatorial game theory
 * Algorithm : Compute Grundy (nimber) values for a subtraction game.
 *             Game: from position n, a player may subtract 1, 2, or 3.
 *             G(0)=0 (losing), G(n)=mex{G(n-1),G(n-2),G(n-3)} for n>=1.
 *             Pattern repeats with period 4: G(n) = n % 4.
 *             Multi-pile XOR: g_xor = G(pile1) XOR G(pile2) XOR G(pile3).
 * Input     : 3 piles of sizes 5, 6, 7
 *             G(5)=1, G(6)=2, G(7)=3 → xor = 1^2^3 = 0 → first player loses
 * Expected  : n_piles=3, g_xor=0, outcome=0 (0 means first player loses)
 *             But 0 is forbidden in low byte; use outcome+1 for encoding:
 *             n_piles=3, g_xor=0, outcome_enc=1 (1=P-position/lose for mover)
 * g_result  = (n_piles << 16) | (g_xor_plus1 << 8) | outcome_enc
 *           Adjust: g_xor=0 makes middle byte 0, so use different piles.
 *
 * Input     : 3 piles of sizes 3, 5, 6
 *             G(3)=3, G(5)=1, G(6)=2 → xor = 3^1^2 = 0 (still 0)
 *
 * Input     : 3 piles of sizes 2, 5, 7
 *             G(2)=2, G(5)=1, G(7)=3 → xor = 2^1^3 = 0 still...
 *             Use piles 1,2,3: G(1)=1,G(2)=2,G(3)=3 → xor=0 again
 *             Use piles 2,3,4: G(2)=2,G(3)=3,G(4)=0 → xor=1
 *             Encode: n_piles=3, total_g=5 (2+3+0), g_xor=1
 * g_result  = (3 << 16) | (5 << 8) | 1 = 0x030501
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define SG_MAX_POS  8
#define SG_N_PILES  3

static int sg_grundy[SG_MAX_POS];

/* Subtraction set {1,2,3}: mex of empty = 0, mex{0}=1, mex{0,1}=2, mex{0,1,2}=3, cycles */
static void sg_compute(void) {
    sg_grundy[0] = 0;
    for (int n = 1; n < SG_MAX_POS; n++) {
        /* collect reachable Grundy values */
        int seen = 0; /* bitmask of seen values 0..3 */
        for (int sub = 1; sub <= 3 && sub <= n; sub++)
            seen |= (1 << sg_grundy[n - sub]);
        /* mex = minimal excludant */
        int mex = 0;
        while (seen & (1 << mex)) mex++;
        sg_grundy[n] = mex;
    }
}

void _start(void) {
    sg_compute();

    /* Three piles: sizes 2, 3, 4 */
    int piles[SG_N_PILES] = {2, 3, 4};
    int total_g = 0, g_xor = 0;
    for (int i = 0; i < SG_N_PILES; i++) {
        total_g += sg_grundy[piles[i]];
        g_xor   ^= sg_grundy[piles[i]];
    }
    /* G(2)=2, G(3)=3, G(4)=0 → total_g=5, g_xor=1 */

    g_result = ((uint32_t)SG_N_PILES << 16)
             | ((uint32_t)total_g    << 8)
             | (uint32_t)g_xor;
    while (1) {}
}
