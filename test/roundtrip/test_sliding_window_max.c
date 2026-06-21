/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Sliding Window Maximum (monotonic deque) fixture.
 *
 * Find the maximum in each sliding window of size k using a monotonic deque
 * that stores indices in decreasing order of their array values.
 *
 * Distinctive decompiler idioms:
 *   1. `if(dq[front]<=i-k) front++` — evict out-of-window index from front
 *   2. `while(front<=back && arr[dq[back]]<=arr[i]) back--` — maintain monotone
 *   3. `dq[++back]=i` — push current index to back
 *   4. `if(i>=k-1) output[out_len++]=arr[dq[front]]` — record window maximum
 *
 * Array {1,3,-1,-3,5,3,6,7}, k=3:
 *   Window maxima: {3,3,5,5,6,7}
 *   out_len = 6
 *   sum     = 3+3+5+5+6+7 = 29
 *   xor     = 3^3^5^5^6^7 = 1
 *
 * g_result = (6<<16) | (29<<8) | 1 = 0x00061D01
 */
#include <stdint.h>

volatile uint32_t g_result;

#define SWM_N 8
#define SWM_K 3

static const int swm_arr[SWM_N] = {1,3,-1,-3,5,3,6,7};

void test_sliding_window_max(void)
{
    static int dq[SWM_N];
    int front = 0, back = -1;
    uint32_t sum = 0, xr = 0;
    int out_len = 0;

    for (int i = 0; i < SWM_N; i++) {
        if (front <= back && dq[front] <= i - SWM_K) front++;
        while (front <= back && swm_arr[dq[back]] <= swm_arr[i]) back--;
        dq[++back] = i;
        if (i >= SWM_K - 1) {
            int mx = swm_arr[dq[front]];
            sum += (uint32_t)mx;
            xr  ^= (uint32_t)mx;
            out_len++;
        }
    }
    /* out_len=6, sum=29, xor=1 */
    g_result = ((uint32_t)out_len << 16) | ((sum & 0xFFu) << 8) | (xr & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_sliding_window_max();
    for (;;);
}
