/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Cantor expansion fixture.
 *
 * The Cantor expansion encodes a permutation as its 0-based rank in
 * lexicographic order.  For permutation p[0..n-1]:
 *
 *   rank = sum_{i=0}^{n-1}  count_smaller_to_right[i] * (n-1-i)!
 *
 * where count_smaller_to_right[i] = |{j > i : p[j] < p[i]}|.
 *
 * Decoding inverts this: repeatedly extract factoradic digits to rebuild
 * the permutation by selecting the idx-th unused element.
 *
 * Three test permutations of length 5 (elements 0..4):
 *   [2,0,4,1,3]  => rank 52
 *   [3,1,0,4,2]  => rank 79
 *   [0,4,2,3,1]  => rank 21
 *
 * We encode, then decode and verify the round-trip.
 *
 * n_tests  = 3
 * sum_rank = 52 + 79 + 21 = 152 = 0x98
 * xor_rank = 52 ^ 79 ^ 21 = 110 = 0x6E
 *
 * g_result = (n_tests << 16) | (sum_rank << 8) | xor_rank = 0x0003986E
 */

typedef unsigned int uint;

extern volatile unsigned g_result;

/* ── Factorial (n <= 7) ────────────────────────────────────────────────────── */

static uint fact(uint n)
{
    uint r = 1;
    for (uint i = 2; i <= n; i++)
        r *= i;
    return r;
}

/* ── Cantor encode ─────────────────────────────────────────────────────────── */

static uint cantor_encode(const uint *p, uint n)
{
    uint rank = 0;
    for (uint i = 0; i < n; i++) {
        uint cnt = 0;
        for (uint j = i + 1; j < n; j++)
            if (p[j] < p[i])
                cnt++;
        rank += cnt * fact(n - 1 - i);
    }
    return rank;
}

/* ── Cantor decode ─────────────────────────────────────────────────────────── */

static void cantor_decode(uint rank, uint n, uint *out)
{
    uint used[8] = {0};   /* bitmask of used elements (n <= 7) */
    for (uint i = 0; i < n; i++) {
        uint f   = fact(n - 1 - i);
        uint idx = rank / f;
        rank     = rank % f;
        /* pick the idx-th unused element */
        uint cnt = 0;
        for (uint v = 0; v < n; v++) {
            if (!used[v]) {
                if (cnt == idx) {
                    out[i] = v;
                    used[v] = 1;
                    break;
                }
                cnt++;
            }
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_cantor_expansion(void)
{
    static const uint perms[3][5] = {
        {2, 0, 4, 1, 3},
        {3, 1, 0, 4, 2},
        {0, 4, 2, 3, 1},
    };
    const uint n = 5;

    uint sum_r = 0, xor_r = 0;
    for (uint k = 0; k < 3; k++) {
        uint rank = cantor_encode(perms[k], n);
        /* round-trip: decode and verify each element matches original */
        uint decoded[5];
        cantor_decode(rank, n, decoded);
        /* If mismatch, corrupt the rank so g_result is obviously wrong */
        for (uint j = 0; j < n; j++)
            if (decoded[j] != perms[k][j])
                rank |= 0x8000u;
        sum_r += rank;
        xor_r ^= rank;
    }

    g_result = (3u << 16) | ((sum_r & 0xFFu) << 8) | (xor_r & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_cantor_expansion();
    for (;;);
}
