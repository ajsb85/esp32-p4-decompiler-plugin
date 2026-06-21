/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Count Distinct Elements in Sliding Window fixture.
 *
 * Count distinct elements in each sliding window of size k using a frequency
 * array: increment freq[x] on entry, decrement on exit; track distinct count.
 *
 * Distinctive decompiler idioms:
 *   1. `freq[arr[i]]++; if(freq[arr[i]]==1) distinct++` — add element
 *   2. `freq[arr[i-k]]--; if(freq[arr[i-k]]==0) distinct--` — remove element
 *   3. `if(i>=k-1) record(distinct)` — emit answer for complete windows
 *   4. `static int freq[8]` — small-domain frequency table
 *
 * Array {1,2,1,3,2,1,1,4}, k=4:
 *   All 5 windows yield 3 distinct elements.
 *   out_len=5, sum=15, xor=3
 *
 * g_result = (5<<16) | (15<<8) | 3 = 0x00050F03
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CDW_N 8
#define CDW_K 4

static const int cdw_arr[CDW_N] = {1,2,1,3,2,1,1,4};

void test_count_distinct_window(void)
{
    static int freq[8];
    int distinct = 0;
    uint32_t sum = 0, xr = 0;
    int out_len = 0;

    for (int i = 0; i < CDW_N; i++) {
        freq[cdw_arr[i]]++;
        if (freq[cdw_arr[i]] == 1) distinct++;
        if (i >= CDW_K) {
            freq[cdw_arr[i - CDW_K]]--;
            if (freq[cdw_arr[i - CDW_K]] == 0) distinct--;
        }
        if (i >= CDW_K - 1) {
            sum += (uint32_t)distinct;
            xr  ^= (uint32_t)distinct;
            out_len++;
        }
    }
    /* out_len=5, sum=15, xor=3 */
    g_result = ((uint32_t)out_len << 16) | ((sum & 0xFFu) << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_count_distinct_window();
    for (;;);
}
