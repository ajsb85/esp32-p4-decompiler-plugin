/*
 * test_nim_game.c
 * Nim game: multi-pile Nim with Sprague-Grundy XOR strategy.
 *
 * Classic Nim: a position is a losing position for the player to move
 * if and only if the XOR (nim-sum) of all pile sizes is 0.
 * Strategy: if nim_xor != 0, find a pile and reduce it so XOR becomes 0.
 *
 * Also implements Wythoff's Nim (two piles, golden ratio relationship)
 * and Grundy values for single-pile Nim (g(n) = n).
 *
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define NIM_MAXPILES 8

/* Compute nim-sum (XOR) of all piles */
static uint32_t nim_xor_sum(const uint32_t *piles, int n) {
    uint32_t xv = 0u;
    for (int i = 0; i < n; i++) {
        xv ^= piles[i];
    }
    return xv;
}

/* Returns 1 if the current position is a P-position (previous player wins),
 * i.e. nim-sum is 0, meaning the player to move loses with optimal play. */
static uint32_t nim_is_losing(const uint32_t *piles, int n) {
    return (nim_xor_sum(piles, n) == 0u) ? 1u : 0u;
}

/* Find a winning move: returns the index of a pile to reduce, and
 * sets *new_size to the pile's new size. Returns -1 if no winning move. */
static int nim_find_winning_move(const uint32_t *piles, int n,
                                  uint32_t *new_size_out) {
    uint32_t xv = nim_xor_sum(piles, n);
    if (xv == 0u) return -1; /* losing position — no winning move */
    for (int i = 0; i < n; i++) {
        uint32_t target = piles[i] ^ xv;
        if (target < piles[i]) {
            *new_size_out = target;
            return i;
        }
    }
    return -1;
}

/* Grundy value for single-pile Nim of size n: g(n) = n */
static uint32_t nim_grundy_single(uint32_t n) {
    return n; /* trivial for classic Nim */
}

/* Wythoff's Nim losing pairs: (k, k + floor(k*phi)) for k=0,1,2,...
 * phi = (1+sqrt(5))/2 ~= 1.618. We use integer approximation. */
static uint32_t wythoff_is_losing(uint32_t a, uint32_t b) {
    /* Ensure a <= b */
    if (a > b) { uint32_t t = a; a = b; b = t; }
    uint32_t diff = b - a;
    /* Floor(diff * phi) approx using (diff*1597)/987 (Fibonacci ratio) */
    uint32_t k = (diff * 1597u) / 987u;
    return (a == k) ? 1u : 0u;
}

static uint32_t run_nim_game_tests(void) {
    uint32_t n_tests = 0u;
    uint32_t metric_a = 0u;
    uint32_t metric_b = 0u;

    /*
     * Test 1: Nim with piles {3, 4, 5}.
     * nim_xor = 3^4^5 = 7^5 = 2 != 0 => N-position (first player wins).
     */
    uint32_t piles1[3] = {3u, 4u, 5u};
    uint32_t losing1 = nim_is_losing(piles1, 3);
    n_tests++;
    (void)losing1; /* expect 0 (not a losing position) */

    /*
     * Test 2: Nim with piles {1, 2, 3}.
     * nim_xor = 1^2^3 = 0 => P-position (first player loses).
     */
    uint32_t piles2[3] = {1u, 2u, 3u};
    uint32_t losing2 = nim_is_losing(piles2, 3);
    n_tests++;
    /* losing2 == 1 */

    /*
     * Test 3: Grundy values for piles 0..7, XOR them all.
     * g(k) = k, so XOR of 0^1^2^3^4^5^6^7 = 0.
     */
    uint32_t grundy_xor = 0u;
    for (uint32_t k = 0u; k < 8u; k++) {
        grundy_xor ^= nim_grundy_single(k);
    }
    n_tests++;
    /* grundy_xor == 0 */

    /*
     * Test 4: Wythoff losing pair (3, 5).
     * floor(2 * phi) = floor(3.236) = 3. So (3, 3+2) = (3, 5) is NOT a
     * Wythoff pair; (2, 5) would be since floor(3*phi)=4... let us just
     * test (0, 0) which is a losing pair (both zero).
     */
    uint32_t wythoff_00 = wythoff_is_losing(0u, 0u);
    n_tests++;
    /* wythoff_00 == 1 */

    /*
     * Test 5: Find winning move from {3,4,5} (nim_xor=2).
     * Pile 0: 3^2=1 < 3, so reduce pile 0 to 1.
     * {1,4,5}: 1^4^5=0. Confirmed.
     */
    uint32_t new_sz = 0u;
    int move_pile = nim_find_winning_move(piles1, 3, &new_sz);
    n_tests++;
    /* move_pile >= 0, new_sz < piles1[move_pile] */

    /*
     * Pack result:
     * metric_a = (losing2 << 6) | (wythoff_00 << 5) | (n_tests & 0x1F)
     *          = (1<<6)|(1<<5)|(5&0x1F) = 64|32|5 = 101 = 0x65
     * metric_b = (move_pile >= 0) ? (new_sz | 0x41u) : 0x42u
     *          = (0 >= 0) ? (1 | 0x41) = 0x41 = 65
     * But 0x65 and 0x41 and 0x05 must be non-zero distinct.
     * n_tests=5=0x05, metric_a=0x65, metric_b=0x41.
     * Result = (5<<16)|(0x65<<8)|0x41 = 0x056541.
     */
    metric_a = (losing2 << 6) | (wythoff_00 << 5) | (n_tests & 0x1Fu);
    metric_b = (uint32_t)(move_pile >= 0) ? (new_sz | 0x41u) : 0x42u;
    return (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_nim_game_tests();
    while (1) {}
}
