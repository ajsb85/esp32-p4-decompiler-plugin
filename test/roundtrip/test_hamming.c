/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Hamming Distance (pairwise + total array) fixture.
 *
 * Hamming distance HD(a, b) = number of bit positions where a and b differ
 *                           = popcount(a XOR b).
 *
 * Distinctive decompiler idioms:
 *   1. `x = a ^ b; while(x){ pc += x&1; x >>= 1; }` — manual popcount of XOR
 *   2. `for bit 0..31: count1 = Σ(arr[i]>>bit)&1; tot += count1*(n-count1)` — total HD
 *   3. Three separate HD pair computations summed
 *
 * Three pairwise Hamming distances:
 *   HD(0b1010, 0b1001)        = HD(10, 9)        = popcount(0b0011) = 2
 *   HD(0xFF,   0x0F)          = HD(255, 15)       = popcount(0xF0)   = 4
 *   HD(0b11001101, 0b01001011)= HD(205, 75)       = popcount(0x86)   = 3
 *
 * Total Hamming distance of array {4, 14, 2} (n=3):
 *   Bit-by-bit contribution: 0+2+2+2 = 6
 *
 * n          = 3   (pair count)
 * pair_sum   = 2+4+3 = 9
 * total_hd   = 6
 *
 * g_result = (n << 16) | (pair_sum << 8) | total_hd = 0x00030906
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Manual popcount (bare metal, no __builtin_popcount) ─────────────────────── */

static int hd_popcount(unsigned x)
{
    int pc = 0;
    while (x) { pc += (int)(x & 1u); x >>= 1; }
    return pc;
}

/* ── Pairwise Hamming distance ───────────────────────────────────────────────── */

static int hamming_dist(int a, int b)
{
    return hd_popcount((unsigned)(a ^ b));
}

/* ── Total Hamming distance across an array ─────────────────────────────────── */

static uint32_t total_hamming(const int *arr, int n)
{
    uint32_t tot = 0;
    for (int bit = 0; bit < 32; bit++) {
        int cnt1 = 0;
        for (int i = 0; i < n; i++)
            if ((arr[i] >> bit) & 1) cnt1++;
        tot += (uint32_t)(cnt1 * (n - cnt1));
    }
    return tot;
}

/* ── Test entry point ────────────────────────────────────────────────────────── */

void test_hamming(void)
{
    /* three pairwise distances */
    uint32_t pair_sum = (uint32_t)(
        hamming_dist(0b1010, 0b1001) +   /* 2 */
        hamming_dist(0xFF,   0x0F)   +   /* 4 */
        hamming_dist(0b11001101, 0b01001011) /* 3 */
    );

    /* total HD of small array */
    static const int hd_arr[3] = {4, 14, 2};
    uint32_t tot_hd = total_hamming(hd_arr, 3);

    /* pair_sum=9, tot_hd=6 */
    g_result = (3u << 16) | (pair_sum << 8) | (tot_hd & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_hamming();
    for (;;);
}
