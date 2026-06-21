/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Maximum Product Subarray (DP) fixture.
 *
 * Tracks both max and min running products because a negative value can
 * flip the minimum to maximum upon multiplying by another negative.
 *
 * Distinctive decompiler idioms:
 *   1. `new_max = max(arr[i], max_h*arr[i], min_h*arr[i])` — 3-way max
 *   2. `new_min = min(arr[i], max_h*arr[i], min_h*arr[i])` — 3-way min (tracks worst)
 *   3. `if(max_h > best) best = max_h` — rolling global best
 *   4. Both max_h and min_h updated simultaneously using old values
 *
 * Test arrays → max product subarrays:
 *   {2,3,-2,4}   →  6   ({2,3})
 *   {-2,0,-1}    →  0   ({0})
 *   {-2,-3,-4}   → 12   ({-3,-4} = 12)
 *
 * n_tests       = 3
 * sum_max_prod  = 6+0+12 = 18  (0x12)
 * xor_max_prod  = 6^0^12       = 10  (0x0A)
 *
 * g_result = (3 << 16) | (18 << 8) | 10 = 0x0003120A
 */
#include <stdint.h>

volatile uint32_t g_result;

static int mp_max3(int a, int b, int c) { return a>b?(a>c?a:c):(b>c?b:c); }
static int mp_min3(int a, int b, int c) { return a<b?(a<c?a:c):(b<c?b:c); }

static int max_product_subarray(const int *arr, int n)
{
    int max_h = arr[0], min_h = arr[0], best = arr[0];
    for (int i = 1; i < n; i++) {
        int a = max_h * arr[i], b = min_h * arr[i];
        int new_max = mp_max3(arr[i], a, b);
        int new_min = mp_min3(arr[i], a, b);
        max_h = new_max;
        min_h = new_min;
        if (max_h > best) best = max_h;
    }
    return best;
}

#define MP_N1 4
#define MP_N2 3
#define MP_N3 3

static const int mp_arr1[MP_N1] = { 2,  3, -2,  4};
static const int mp_arr2[MP_N2] = {-2,  0, -1};
static const int mp_arr3[MP_N3] = {-2, -3, -4};

void test_max_product(void)
{
    int r1 = max_product_subarray(mp_arr1, MP_N1); /*  6 */
    int r2 = max_product_subarray(mp_arr2, MP_N2); /*  0 */
    int r3 = max_product_subarray(mp_arr3, MP_N3); /* 12 */

    uint32_t sum_p = (uint32_t)(r1 + r2 + r3); /* 18 */
    uint32_t xor_p = (uint32_t)(r1 ^ r2 ^ r3); /* 10 */

    g_result = (3u << 16) | ((sum_p & 0xFFu) << 8) | (xor_p & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_max_product();
    for (;;);
}
