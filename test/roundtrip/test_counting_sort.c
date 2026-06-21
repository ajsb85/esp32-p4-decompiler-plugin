/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Counting sort (stable) round-trip fixture.
 *
 * Linear-time stable counting sort for a fixed integer range [0, MAX_VAL].
 * Three distinct decompiler idioms:
 *
 *  1. Frequency count:    count[arr[i]]++
 *  2. Prefix-sum:         count[i] += count[i-1]
 *  3. Stable output (right-to-left): out[--count[arr[i]]] = arr[i]
 *
 * Input (n=10, range 0..9):
 *   {4, 2, 2, 8, 3, 3, 1, 4, 1, 8}
 *
 * Frequency:  [0, 2, 2, 2, 2, 0, 0, 0, 2, 0]  (index = value)
 * Prefix sum: [0, 2, 4, 6, 8, 8, 8, 8, 10, 10]
 * Sorted out: {1, 1, 2, 2, 3, 3, 4, 4, 8, 8}
 *
 *   sum_sorted = 1+1+2+2+3+3+4+4+8+8 = 36 = 0x24
 *   xor_sorted = 1^1^2^2^3^3^4^4^8^8 = 0   (all pairs cancel)
 *   n = 10
 *
 * g_result = (n << 16) | (sum_sorted << 8) | xor_sorted = 0x000A2400
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Counting sort ────────────────────────────────────────────────────────── */

#define CS_N       10
#define CS_MAXVAL  9

static int cs_count[CS_MAXVAL + 1];
static int cs_out[CS_N];

static void counting_sort(const int *arr, int n)
{
    /* Step 1: frequency count */
    for (int i = 0; i <= CS_MAXVAL; i++)
        cs_count[i] = 0;
    for (int i = 0; i < n; i++)
        cs_count[arr[i]]++;

    /* Step 2: prefix sum (cumulative count) */
    for (int i = 1; i <= CS_MAXVAL; i++)
        cs_count[i] += cs_count[i - 1];

    /* Step 3: stable output (right-to-left preserves input order) */
    for (int i = n - 1; i >= 0; i--)
        cs_out[--cs_count[arr[i]]] = arr[i];
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_counting_sort(void)
{
    static const int arr[CS_N] = {4, 2, 2, 8, 3, 3, 1, 4, 1, 8};
    counting_sort(arr, CS_N);

    uint32_t sum_s = 0, xor_s = 0;
    for (int i = 0; i < CS_N; i++) {
        sum_s += (uint32_t)cs_out[i];
        xor_s ^= (uint32_t)cs_out[i];
    }

    g_result = ((uint32_t)CS_N << 16)
             | (sum_s << 8)
             | (xor_s & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_counting_sort();
    for (;;);
}
