/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Prefix XOR array (range XOR queries) fixture.
 *
 * Build a prefix XOR array px[] where px[i] = arr[0]^arr[1]^...^arr[i-1].
 * Range XOR query [l,r] (inclusive) is px[r+1] ^ px[l] in O(1).
 *
 * Distinctive decompiler idioms:
 *   1. `px[i+1] = px[i] ^ arr[i]` — prefix XOR build (XOR analogue of prefix sum)
 *   2. `result = px[r+1] ^ px[l]` — O(1) range XOR via prefix table
 *   3. `px[0] = 0` — identity seed for XOR prefix
 *
 * Array: {1, 2, 3, 4, 5, 6, 7, 8}  (n=8)
 * PX:    {0, 1, 3, 0, 4, 1, 7, 0, 8}
 * Queries: xorRange(0,3)=4, xorRange(2,5)=4, xorRange(0,7)=8
 *
 * n_queries  = 3
 * sum_results = 4 + 4 + 8 = 16  (0x10)
 * xor_results = 4 ^ 4 ^ 8 = 8
 *
 * g_result = (n_queries << 16) | (sum_results << 8) | xor_results = 0x00031008
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PX_N 8

static const int px_arr[PX_N] = {1, 2, 3, 4, 5, 6, 7, 8};
static int px_table[PX_N + 1];

static const int px_ql[3] = {0, 2, 0};
static const int px_qr[3] = {3, 5, 7};

void test_prefix_xor(void)
{
    px_table[0] = 0;
    for (int i = 0; i < PX_N; i++)
        px_table[i + 1] = px_table[i] ^ px_arr[i];

    uint32_t pxs = 0, pxx = 0;
    for (int i = 0; i < 3; i++) {
        uint32_t r = (uint32_t)(px_table[px_qr[i] + 1] ^ px_table[px_ql[i]]);
        pxs += r;
        pxx ^= r;
    }

    g_result = (3u << 16) | ((pxs & 0xFFu) << 8) | (pxx & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_prefix_xor();
    for (;;);
}
