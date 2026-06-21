/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — LSD radix sort (base-16, 2-pass) round-trip fixture.
 *
 * Least-Significant-Digit radix sort on uint8_t values using base 16
 * (nibble-at-a-time), two stable counting-sort passes:
 *
 *   Pass 1: key = arr[i] & 0xF   (low nibble)
 *   Pass 2: key = tmp[i] >> 4    (high nibble)
 *
 * Each pass is a stable counting sort:
 *   1. count[key]++
 *   2. prefix sum left-to-right
 *   3. right-to-left output scan for stability: out[--count[key]] = val
 *
 * Input (n=8): {45, 12, 78, 23, 56, 89, 34, 67}
 *
 * After pass 1 (by low nibble 2,3,7,8,9,C,D,E):
 *   tmp = {34, 67, 23, 56, 89, 12, 45, 78}
 *
 * After pass 2 (by high nibble 0,1,2,2,3,4,4,5):
 *   out = {12, 23, 34, 45, 56, 67, 78, 89}
 *
 *   last   = out[7] = 89 = 0x59
 *   xor    = 12^23^34^45^56^67^78^89 = 120 = 0x78
 *   n      = 8
 *
 * g_result = (n << 16) | (last << 8) | xor = 0x00085978
 *
 * Recognizable decompiler idioms:
 *   arr[i] & 0xF               — low-nibble key extraction
 *   tmp[i] >> 4                — high-nibble key extraction
 *   out[--cnt[key]] = val      — stable right-to-left output (shared with counting_sort)
 *   cnt[i] += cnt[i-1]         — prefix-sum accumulation
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Radix sort ────────────────────────────────────────────────────────────── */

#define RADIX_N 8

static uint8_t radix_tmp[RADIX_N];
static uint8_t radix_out[RADIX_N];

static void radix_sort_u8(const uint8_t *arr, int n)
{
    uint8_t cnt[16];

    /* Pass 1: sort by low nibble */
    for (int i = 0; i < 16; i++) cnt[i] = 0;
    for (int i = 0; i < n; i++) cnt[arr[i] & 0xF]++;
    for (int i = 1; i < 16; i++) cnt[i] = (uint8_t)(cnt[i] + cnt[i - 1]);
    for (int i = n - 1; i >= 0; i--)
        radix_tmp[--cnt[arr[i] & 0xF]] = arr[i];

    /* Pass 2: sort by high nibble */
    for (int i = 0; i < 16; i++) cnt[i] = 0;
    for (int i = 0; i < n; i++) cnt[radix_tmp[i] >> 4]++;
    for (int i = 1; i < 16; i++) cnt[i] = (uint8_t)(cnt[i] + cnt[i - 1]);
    for (int i = n - 1; i >= 0; i--)
        radix_out[--cnt[radix_tmp[i] >> 4]] = radix_tmp[i];
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_radix_sort(void)
{
    static const uint8_t arr[RADIX_N] = {45, 12, 78, 23, 56, 89, 34, 67};

    radix_sort_u8(arr, RADIX_N);   /* out = {12,23,34,45,56,67,78,89} */

    uint32_t xor_r = 0;
    for (int i = 0; i < RADIX_N; i++)
        xor_r ^= (uint32_t)radix_out[i];   /* = 120 */

    g_result = ((uint32_t)RADIX_N << 16)
             | ((uint32_t)radix_out[RADIX_N - 1] << 8)
             | (xor_r & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_radix_sort();
    for (;;);
}
