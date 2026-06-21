/* test_berlekamp_massey.c
 * Berlekamp-Massey algorithm: find the shortest LFSR that generates
 * a given binary sequence.  Bare-metal, no stdlib headers.
 *
 * g_result = (n_tests << 16) | (metric_a << 8) | metric_b
 *   n_tests  = 7   (number of test sequences processed)
 *   metric_a = length of LFSR found for sequence 0
 *   metric_b = XOR of all LFSR lengths mod 256
 */

typedef unsigned int  uint32_t;
typedef unsigned char uint8_t;

extern volatile unsigned g_result;

/* ── Berlekamp-Massey (GF(2)) ─────────────────────────────────────── */

/*
 * Returns length of the shortest LFSR (in bits) that generates seq[0..n-1].
 * C[], B[] are connection polynomials encoded as uint32_t bit arrays.
 */
static int bm_gf2(const uint8_t *seq, int n)
{
    /* connection poly C, last-update poly B */
    uint32_t C = 1u; /* C = 1 */
    uint32_t B = 1u; /* B = 1 (shift register) */
    int L = 0;       /* current LFSR length */
    int m = 1;       /* steps since last length change */

    int i, j;
    for (i = 0; i < n; i++) {
        /* Compute discrepancy d */
        uint8_t d = seq[i];
        for (j = 1; j <= L; j++) {
            if ((C >> j) & 1u)
                d ^= seq[i - j];
        }

        if (d == 0) {
            m++;
        } else if (2 * L <= i) {
            /* Update: T = C, C = C XOR B<<m, B = T, L = i+1-L */
            uint32_t T = C;
            C ^= (B << m);
            B = T;
            L = i + 1 - L;
            m = 1;
        } else {
            C ^= (B << m);
            m++;
        }
    }
    return L;
}

/* ── Test sequences ───────────────────────────────────────────────── */

/* seq0: period-4 sequence 1,0,1,1,1,0,1,1 — LFSR length should be 4 */
static const uint8_t seq0[] = {1,0,1,1,1,0,1,1,1,0,1,1};
/* seq1: all-ones — LFSR of length 1 */
static const uint8_t seq1[] = {1,1,1,1,1,1,1,1};
/* seq2: alternating 1,0 — LFSR of length 2 */
static const uint8_t seq2[] = {1,0,1,0,1,0,1,0};
/* seq3: Fibonacci-like mod 2: 0,1,1,0,1,1,0,1 */
static const uint8_t seq3[] = {0,1,1,0,1,1,0,1,1,0,1,1};
/* seq4: single 1 then zeros — LFSR length 1 */
static const uint8_t seq4[] = {1,0,0,0,0,0,0,0};
/* seq5: random-like length-12: 1,1,0,1,0,0,1,0,1,1,0,1 */
static const uint8_t seq5[] = {1,1,0,1,0,0,1,0,1,1,0,1};
/* seq6: maximal LFSR tap x^4+x+1 produces len 4 */
static const uint8_t seq6[] = {1,0,0,0,1,0,0,1,1,0,1,0,1,1,1,1};

void _start(void)
{
    int n_tests = 7;

    int l0 = bm_gf2(seq0, 12);
    int l1 = bm_gf2(seq1, 8);
    int l2 = bm_gf2(seq2, 8);
    int l3 = bm_gf2(seq3, 12);
    int l4 = bm_gf2(seq4, 8);
    int l5 = bm_gf2(seq5, 12);
    int l6 = bm_gf2(seq6, 16);

    int metric_a = l0; /* LFSR length for seq0 */
    int metric_b = (l0 ^ l1 ^ l2 ^ l3 ^ l4 ^ l5 ^ l6) & 0xFF;

    g_result = ((unsigned)n_tests << 16) | ((unsigned)metric_a << 8) | (unsigned)metric_b;
}
