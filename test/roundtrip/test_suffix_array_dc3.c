/* test_suffix_array_dc3.c — Suffix Array via DC3/Skew algorithm
 * Self-contained, 32-bit arithmetic only.
 * Build:
 *   riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f \
 *     -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_suffix_array_dc3.c
 */

#include <stdint.h>

/* ── DC3 / Skew Suffix Array ─────────────────────────────────────────────── */

#define DC3_MAXN  64

/* leq for (a1,a2) vs (b1,b2) */
static int dc3_leq2(uint32_t a1, uint32_t a2, uint32_t b1, uint32_t b2) {
    return (a1 < b1) || (a1 == b1 && a2 <= b2);
}

/* leq for (a1,a2,a3) vs (b1,b2,b3) */
static int dc3_leq3(uint32_t a1, uint32_t a2, uint32_t a3,
                    uint32_t b1, uint32_t b2, uint32_t b3) {
    return (a1 < b1) || (a1 == b1 && dc3_leq2(a2,a3,b2,b3));
}

/* Counting sort: sort sa[0..n-1] by key[sa[i]], keys in [0..maxv] */
static void dc3_count_sort(int *sa, int n, const uint32_t *key, uint32_t maxv,
                           int *out, uint32_t *cnt) {
    for (uint32_t i = 0; i <= maxv; i++) cnt[i] = 0;
    for (int i = 0; i < n; i++) cnt[key[sa[i]]]++;
    for (uint32_t i = 1; i <= maxv; i++) cnt[i] += cnt[i-1];
    for (int i = n-1; i >= 0; i--) out[--cnt[key[sa[i]]]] = sa[i];
    for (int i = 0; i < n; i++) sa[i] = out[i];
}

/* Global scratch arrays to avoid VLAs and stack issues */
static uint32_t dc3_keys[DC3_MAXN * 3];   /* key arrays (offset by position) */
static int      dc3_sa12  [DC3_MAXN];
static int      dc3_sa0   [DC3_MAXN];
static int      dc3_rank12[DC3_MAXN + 3];
static int      dc3_buf   [DC3_MAXN];
static uint32_t dc3_cnt   [DC3_MAXN + 1];

/* Build suffix array for s[0..n-1] into sa[0..n-1].
 * s must have s[n]=s[n+1]=s[n+2]=0. Alphabet [1..maxv].
 */
static void dc3_build(const uint32_t *s, int *sa, int n, uint32_t maxv) {
    if (n == 1) { sa[0] = 0; return; }

    int n12 = 0;
    for (int i = 0; i < DC3_MAXN + 3; i++) dc3_rank12[i] = 0;

    /* collect mod-1 and mod-2 positions */
    for (int i = 0; i < n + (n % 3 == 1 ? 1 : 0); i++)
        if (i % 3 != 0) dc3_sa12[n12++] = i;

    /* radix sort dc3_sa12 by triple (s[i],s[i+1],s[i+2]) */
    /* build key arrays indexed by position [0..n+2] */
    for (int i = 0; i < n12; i++) {
        int p = dc3_sa12[i];
        dc3_keys[p*3 + 0] = s[p];
        dc3_keys[p*3 + 1] = s[p+1];
        dc3_keys[p*3 + 2] = s[p+2];
    }
    /* sort by key2, key1, key0 (stable) using indexed key extraction */
    /* We sort dc3_sa12 by dc3_keys[sa12[i]*3+2], etc. */
    /* Adapter: sort by key offset 2, then 1, then 0 */
    for (int pass = 2; pass >= 0; pass--) {
        /* build per-position key array for this pass */
        uint32_t kp[DC3_MAXN];
        for (int i = 0; i < n12; i++) kp[dc3_sa12[i]] = dc3_keys[dc3_sa12[i]*3 + pass];
        dc3_count_sort(dc3_sa12, n12, kp, maxv, dc3_buf, dc3_cnt);
    }

    /* assign ranks */
    int cur = 0;
    uint32_t prev0 = (uint32_t)-1, prev1 = (uint32_t)-1, prev2 = (uint32_t)-1;
    for (int i = 0; i < n12; i++) {
        int p = dc3_sa12[i];
        if (s[p] != prev0 || s[p+1] != prev1 || s[p+2] != prev2) {
            cur++;
            prev0 = s[p]; prev1 = s[p+1]; prev2 = s[p+2];
        }
        dc3_rank12[p] = cur;
    }

    /* sort mod-0 positions using dc3_rank12 at position+1 */
    int n0 = 0;
    for (int i = 0; i < n12; i++)
        if (dc3_sa12[i] % 3 == 1) dc3_sa0[n0++] = dc3_sa12[i] - 1;
    {
        uint32_t k0[DC3_MAXN];
        for (int i = 0; i < n0; i++) k0[dc3_sa0[i]] = s[dc3_sa0[i]];
        dc3_count_sort(dc3_sa0, n0, k0, maxv, dc3_buf, dc3_cnt);
    }

    /* merge dc3_sa12 and dc3_sa0 */
    int p12 = 0, p0 = 0, p = 0;
    while (p12 < n12 && p0 < n0) {
        int i = dc3_sa12[p12], j = dc3_sa0[p0];
        int cmp;
        if (i % 3 == 1) {
            cmp = dc3_leq2(s[i],  (uint32_t)dc3_rank12[i+1],
                           s[j],  (uint32_t)dc3_rank12[j+1]);
        } else {
            cmp = dc3_leq3(s[i],  s[i+1], (uint32_t)dc3_rank12[i+2],
                           s[j],  s[j+1], (uint32_t)dc3_rank12[j+2]);
        }
        if (cmp) { sa[p++] = i; p12++; }
        else     { sa[p++] = j; p0++;  }
    }
    while (p12 < n12) sa[p++] = dc3_sa12[p12++];
    while (p0  < n0 ) sa[p++] = dc3_sa0 [p0++ ];
}

/* ── test driver ─────────────────────────────────────────────────────────── */

volatile uint32_t g_result;

static void run_suffix_array_dc3(void) {
    uint32_t s[DC3_MAXN + 3];
    int      sa[DC3_MAXN];

    /* test 1: "banana" -> b=2,a=1,n=14,a=1,n=14,a=1
     * expected SA: [5,3,1,0,4,2] */
    {
        const uint8_t raw[] = {2, 1, 14, 1, 14, 1};
        int n = 6;
        for (int i = 0; i < n; i++) s[i] = raw[i];
        s[n] = s[n+1] = s[n+2] = 0;
        dc3_build(s, sa, n, 14);
    }
    int ok1 = (sa[0] == 5 && sa[1] == 3 && sa[2] == 1);

    /* test 2: "abab" -> a=1,b=2,a=1,b=2
     * expected SA: [2,0,3,1] */
    {
        const uint8_t raw[] = {1, 2, 1, 2};
        int n = 4;
        for (int i = 0; i < n; i++) s[i] = raw[i];
        s[n] = s[n+1] = s[n+2] = 0;
        dc3_build(s, sa, n, 2);
    }
    int ok2 = (sa[0] == 2 && sa[1] == 0);

    /* test 3: "aab" -> a=1,a=1,b=2
     * expected SA: [1,0,2] */
    {
        const uint8_t raw[] = {1, 1, 2};
        int n = 3;
        for (int i = 0; i < n; i++) s[i] = raw[i];
        s[n] = s[n+1] = s[n+2] = 0;
        dc3_build(s, sa, n, 2);
    }
    int ok3 = (sa[0] == 1 && sa[1] == 0 && sa[2] == 2);

    /* n_tests=3, metric_a=ok1*7=7=0x07, metric_b=ok2+ok3+3=5=0x05 */
    uint32_t n_tests  = 3;
    uint32_t metric_a = (uint32_t)(ok1 ? 7 : 1);    /* 0x07 */
    uint32_t metric_b = (uint32_t)(ok2 + ok3 + 3);  /* 0x05 */
    g_result = (n_tests << 16) | (metric_a << 8) | metric_b;
    /* expected: 0x00030705 */
}

void _start(void) {
    run_suffix_array_dc3();
    while (1) {}
}
