/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Stern-Brocot tree / mediant rational approximation fixture.
 *
 * The Stern-Brocot tree enumerates all positive rationals exactly once.
 * Given a target fraction p/q we search the tree top-down:
 *   start with left = 0/1, right = 1/0, mediant = 1/1
 *   if mediant == p/q  => found at depth d
 *   if mediant <  p/q  => go right: left  = mediant
 *   if mediant >  p/q  => go left:  right = mediant
 *
 * Three test fractions:
 *   5/8  found at depth 5
 *   3/7  found at depth 5
 *   7/5  found at depth 5
 *
 * n_tests  = 3
 * sum_depth = 5 + 5 + 5 = 15 = 0x0F
 * xor_depth = 5 ^ 5 ^ 5 = 5  = 0x05
 *
 * g_result = (n_tests << 16) | (sum_depth << 8) | xor_depth = 0x00030F05
 */

typedef unsigned int uint;
typedef unsigned char uchar;

extern volatile unsigned g_result;

/* ── Stern-Brocot tree search ─────────────────────────────────────────────── */

static uint sb_depth(uint p, uint q)
{
    uint ln = 0, ld = 1;   /* left  boundary numerator / denominator */
    uint rn = 1, rd = 0;   /* right boundary numerator / denominator */
    uint depth = 0;

    for (;;) {
        uint mn = ln + rn;  /* mediant */
        uint md = ld + rd;
        depth++;

        if (mn == p && md == q)
            return depth;

        /* Compare mediant m/md with target p/q:
         *   mn/md < p/q  <=>  mn*q < p*md  */
        if (mn * q < p * md) {
            ln = mn;
            ld = md;
        } else {
            rn = mn;
            rd = md;
        }
    }
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_stern_brocot(void)
{
    /* target fractions (p, q) */
    static const uint tp[] = {5, 3, 7};
    static const uint tq[] = {8, 7, 5};

    uint sum_d = 0, xor_d = 0;
    for (uint k = 0; k < 3; k++) {
        uint d = sb_depth(tp[k], tq[k]);
        sum_d += d;
        xor_d ^= d;
    }

    g_result = (3u << 16) | ((sum_d & 0xFFu) << 8) | (xor_d & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_stern_brocot();
    for (;;);
}
