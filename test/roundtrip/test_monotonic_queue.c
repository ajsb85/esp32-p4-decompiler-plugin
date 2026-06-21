#include <stdint.h>

/* Sliding window maximum using a monotonic deque.
 * Deque stores indices; front holds index of current window max.
 * Invariant: deque is decreasing (arr[dq[0]] >= arr[dq[1]] >= ...).
 * g_result encodes (n, sum_of_maxes, xor_of_maxes). */

volatile uint32_t g_result;

void test_monotonic_queue(void) {
    int arr[] = {1, 3, -1, -3, 5, 3, 6, 7};
    int n = 8, k = 3;
    int dq[8], head = 0, tail = 0;
    int maxes[8]; int mc = 0;

    for (int i = 0; i < n; i++) {
        /* Remove indices outside the window */
        while (head < tail && dq[head] <= i - k) head++;
        /* Maintain decreasing invariant */
        while (head < tail && arr[dq[tail - 1]] <= arr[i]) tail--;
        dq[tail++] = i;
        /* Window is full after first k elements */
        if (i >= k - 1) maxes[mc++] = arr[dq[head]];
    }

    /* maxes = {3,3,5,5,6,7}; sum=29, xor=1 */
    int s = 0, x = 0;
    for (int i = 0; i < mc; i++) { s += maxes[i]; x ^= maxes[i]; }
    g_result = ((uint32_t)n << 16) | ((uint32_t)s << 8) | (uint32_t)x; /* 0x00081D01 */
}

__attribute__((noreturn)) void _start(void) {
    test_monotonic_queue();
    for (;;);
}
