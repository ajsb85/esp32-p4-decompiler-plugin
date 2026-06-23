/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — DC3 / Skew suffix array construction.
 *
 * DC3 builds a suffix array by sampling 2/3 of positions (i%3 != 0),
 * recursing, then merging with the remaining 1/3 (i%3 == 0) using rank
 * comparisons.
 *
 * Distinctive decompiler idioms:
 *   1. i%3 != 0 — sample selection bitmask
 *   2. Three-character triple comparison per sample position
 *   3. rank12[] — interleaved rank arrays for mod-1 and mod-2 positions
 *   4. dc3_radix() called three times (stable sort on 3 keys)
 *   5. Merge: pos%3==1 uses rank12[pos/3], else rank12[pos/3 + half]
 *
 * Input: "banana" (n=6); expected SA = [5,3,1,0,4,2]
 *   SA[0]=5 (suffix "a"), SA[5]=2 (suffix "nana")
 *
 * g_result = (n<<16)|(SA[0]<<8)|SA[5] = (6<<16)|(5<<8)|2 = 0x060502
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SA_MAXN 16

static void isort3(int *s, int *sa, int n, int K, int off)
{
    int cnt[SA_MAXN]; for(int _i=0;_i<SA_MAXN;_i++) cnt[_i]=0;
    for (int i = 0; i < n; i++)
        cnt[(sa[i]+off < 7 ? s[sa[i]+off] : 0)]++;
    for (int i = 1; i < K; i++) cnt[i] += cnt[i-1];
    int tmp[SA_MAXN];
    for (int i = n-1; i >= 0; i--)
        tmp[--cnt[(sa[i]+off < 7 ? s[sa[i]+off] : 0)]] = sa[i];
    for (int i = 0; i < n; i++) sa[i] = tmp[i];
}

void test_suffix_array_dc3(void)
{
    /* "banana\0": b=2,a=1,n=3; sentinel s[6]=0 */
    int s[7] = {2,1,3,1,3,1,0};
    int n = 6, K = 4;

    /* Step 1: collect sample positions i%3!=0 */
    int s12[SA_MAXN], n12 = 0;
    for (int i = 0; i < n; i++)
        if (i%3 != 0) s12[n12++] = i;

    /* Step 2: radix sort samples on 3 characters */
    int sa12[SA_MAXN];
    for (int i = 0; i < n12; i++) sa12[i] = s12[i];
    isort3(s, sa12, n12, K, 2);
    isort3(s, sa12, n12, K, 1);
    isort3(s, sa12, n12, K, 0);

    /* Step 3: assign ranks */
    int rank12[SA_MAXN]; for(int _j=0;_j<SA_MAXN;_j++) rank12[_j]=0;
    int r = 0;
    for (int i = 0; i < n12; i++) {
        int p = sa12[i];
        if (i == 0 || s[p] != s[sa12[i-1]] ||
            (p+1<7?s[p+1]:0) != (sa12[i-1]+1<7?s[sa12[i-1]+1]:0) ||
            (p+2<7?s[p+2]:0) != (sa12[i-1]+2<7?s[sa12[i-1]+2]:0)) r++;
        rank12[p%3==1 ? p/3 : p/3 + (n12+1)/2] = r;
    }

    /* Step 4: sort s0 positions (i%3==0) by (s[i], rank12[i+1]) */
    int s0[SA_MAXN], n0 = 0;
    for (int i = 0; i < n12; i++)
        if (sa12[i]%3 == 1) s0[n0++] = sa12[i]-1;
    /* simple insertion sort for small n */
    for (int i = 1; i < n0; i++) {
        int key = s0[i], j = i-1;
        while (j >= 0) {
            int a = s0[j], b = key;
            int ca = s[a], cb = s[b];
            int ra = rank12[a/3 + (n12+1)/2];
            int rb = rank12[b/3 + (n12+1)/2];
            if (ca > cb || (ca == cb && ra > rb)) { s0[j+1] = s0[j]; j--; }
            else break;
        }
        s0[j+1] = key;
    }

    /* Step 5: merge sa12 and s0 */
    int sa[SA_MAXN]; int i = 0, j = 0, k = 0;
    while (i < n12 && j < n0) {
        int p = sa12[i], q = s0[j];
        int cmp;
        if (p%3 == 1) {
            int sp = s[p], sq = s[q];
            int rp = rank12[p/3], rq = rank12[q/3 + (n12+1)/2];
            cmp = sp != sq ? sp - sq : rp - rq;
        } else {
            int sp0 = s[p], sq0 = s[q];
            int sp1 = p+1<7?s[p+1]:0, sq1 = q+1<7?s[q+1]:0;
            int rp = rank12[p/3 + (n12+1)/2], rq = rank12[q/3 + 1];
            cmp = sp0 != sq0 ? sp0-sq0 : sp1 != sq1 ? sp1-sq1 : rp-rq;
        }
        if (cmp <= 0) sa[k++] = p, i++;
        else          sa[k++] = q, j++;
    }
    while (i < n12) sa[k++] = sa12[i++];
    while (j < n0)  sa[k++] = s0[j++];

    /* SA[0]=5,SA[1]=3,SA[2]=1,SA[3]=0,SA[4]=4,SA[5]=2 */
    g_result = ((uint32_t)n << 16)
             | ((uint32_t)(sa[0] & 0xFF) << 8)
             | ((uint32_t)(sa[n-1] & 0xFF));
}

__attribute__((noreturn)) void _start(void)
{
    test_suffix_array_dc3();
    for (;;);
}
