/*
 * test_largest_div_subset.c — largest divisible subset via sort + DP.
 *
 * Sort array then: dp[i] = max(dp[j]+1) for j<i where arr[i]%arr[j]==0
 * Reconstruct via parent[] array.
 *
 * Input: {1,2,3,6,24,8} (n=6)
 * Sorted: {1,2,3,6,8,24}
 * Largest subset: {1,2,6,24} length=4, xor=1^2^6^24=29=0x1D
 *
 * g_result = (6<<16)|(4<<8)|29 = 0x0006041D
 */
#include <stdint.h>

#define MAXN 16

static void sort_asc(int *a, int n)
{
    for (int i = 1; i < n; i++) {
        int key = a[i], j = i - 1;
        while (j >= 0 && a[j] > key) { a[j+1] = a[j]; j--; }
        a[j+1] = key;
    }
}

volatile uint32_t g_result;

int main(void)
{
    int arr[MAXN];
    arr[0]=1; arr[1]=2; arr[2]=3; arr[3]=6; arr[4]=24; arr[5]=8;
    int n = 6;
    sort_asc(arr, n);

    int dp[MAXN], parent[MAXN];
    for (int i = 0; i < n; i++) { dp[i] = 1; parent[i] = -1; }

    int best = 1, best_idx = 0;
    for (int i = 1; i < n; i++) {
        for (int j = 0; j < i; j++) {
            if (arr[i] % arr[j] == 0 && dp[j] + 1 > dp[i]) {
                dp[i] = dp[j] + 1;
                parent[i] = j;
            }
        }
        if (dp[i] > best) { best = dp[i]; best_idx = i; }
    }

    uint32_t xor_sub = 0;
    int idx = best_idx;
    while (idx != -1) {
        xor_sub ^= (uint32_t)arr[idx];
        idx = parent[idx];
    }

    g_result = ((uint32_t)n    << 16)
             | ((uint32_t)best <<  8)
             | (xor_sub & 0xFFu);
    /* expected: (6<<16)|(4<<8)|29 = 0x0006041D */
    return 0;
}
