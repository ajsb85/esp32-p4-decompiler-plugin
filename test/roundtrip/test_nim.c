/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Nim Game (Sprague-Grundy XOR) fixture.
 *
 * Classic Nim: given piles of stones, two players alternately remove any
 * positive number from one pile. The player who takes the last stone wins.
 *
 * Sprague-Grundy theorem: the current player LOSES iff XOR of all pile
 * sizes equals 0. Winning move: pick pile i where pile[i] ^ nim_xor < pile[i]
 * and reduce pile[i] to pile[i] ^ nim_xor.
 *
 * Distinctive decompiler idioms:
 *   1. `nim_xor = pile[0] ^ pile[1] ^ ... ^ pile[n-1]` — XOR all piles
 *   2. `if (nim_xor == 0) { current player loses }` — losing condition
 *   3. `winning_pile = pile[i] where pile[i] ^ nim_xor < pile[i]` — find move
 *   4. `reduce pile[i] to pile[i] ^ nim_xor` — execute winning move
 *
 * Games tested (pile sizes, nim_xor, outcome):
 *   {3,4,5}     → 3^4^5=2   → WIN
 *   {1,2,3}     → 1^2^3=0   → LOSE
 *   {4,4}       → 4^4=0     → LOSE
 *   {3,3,3,3}   → 3^3^3^3=0 → LOSE
 *   {2,2}       → 2^2=0     → LOSE
 *
 * n_games   = 5
 * n_wins    = 1  (only {3,4,5})
 * xor_all   = 2^0^0^0^0 = 2
 *
 * g_result = (n_games << 16) | (n_wins << 8) | xor_all = 0x00050102
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Nim helpers ─────────────────────────────────────────────────────────── */

static int nim_xor(const int *piles, int n)
{
    int x = 0;
    for (int i = 0; i < n; i++) x ^= piles[i];
    return x;
}

static int nim_find_winning_move(const int *piles, int n, int xv, int *reduce_to)
{
    for (int i = 0; i < n; i++) {
        if ((piles[i] ^ xv) < piles[i]) {
            *reduce_to = piles[i] ^ xv;
            return i;
        }
    }
    return -1; /* losing position, no winning move */
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_nim(void)
{
    static const int piles[5][4] = {
        {3, 4, 5, 0},  /* nim_xor=2 → WIN */
        {1, 2, 3, 0},  /* nim_xor=0 → LOSE */
        {4, 4, 0, 0},  /* nim_xor=0 → LOSE */
        {3, 3, 3, 3},  /* nim_xor=0 → LOSE */
        {2, 2, 0, 0}   /* nim_xor=0 → LOSE */
    };
    static const int sizes[5] = {3, 3, 2, 4, 2};

    uint32_t n_wins = 0, xor_all = 0;

    for (int g = 0; g < 5; g++) {
        int xv = nim_xor(piles[g], sizes[g]);
        xor_all ^= (uint32_t)xv;
        if (xv != 0) {
            n_wins++;
            /* verify winning move exists */
            int reduce_to = 0;
            nim_find_winning_move(piles[g], sizes[g], xv, &reduce_to);
        }
    }

    /* n_wins=1, xor_all=2 */
    g_result = ((uint32_t)5 << 16) | (n_wins << 8) | (xor_all & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_nim();
    for (;;);
}
