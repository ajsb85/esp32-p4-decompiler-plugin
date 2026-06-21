/*
 * test_turbulent.c — longest turbulent subarray (alternating DP)
 *
 * Array {9,4,2,10,7,8,8,1,9} (n=9).
 * dp_inc[i] = turbulent subarray length ending at i with arr[i-1]<arr[i]
 * dp_dec[i] = turbulent subarray length ending at i with arr[i-1]>arr[i]
 *
 * Result: max_len=5 (subarray arr[1..5]={4,2,10,7,8})
 * xor_arr = 9^4^2^10^7^8^8^1^9 = 10 = 0x0A
 * g_result = (9<<16)|(5<<8)|10 = 0x0009050A
 */
#include <stdint.h>

#define MAXN 16

volatile uint32_t g_result;

int main(void)
{
    static const int arr[] = {9,4,2,10,7,8,8,1,9};
    int n = 9;

    int dp_inc[MAXN], dp_dec[MAXN];
    dp_inc[0] = dp_dec[0] = 1;

    int max_len = 1;
    for (int i = 1; i < n; i++) {
        if (arr[i] > arr[i-1]) {
            dp_inc[i] = dp_dec[i-1] + 1;
            dp_dec[i] = 1;
        } else if (arr[i] < arr[i-1]) {
            dp_dec[i] = dp_inc[i-1] + 1;
            dp_inc[i] = 1;
        } else {
            dp_inc[i] = dp_dec[i] = 1;
        }
        int best = dp_inc[i] > dp_dec[i] ? dp_inc[i] : dp_dec[i];
        if (best > max_len) max_len = best;
    }

    uint32_t xor_arr = 0;
    for (int i = 0; i < n; i++) xor_arr ^= (uint32_t)arr[i];

    g_result = ((uint32_t)n       << 16)
             | ((uint32_t)max_len <<  8)
             | (xor_arr & 0xFFu);
    /* expected: (9<<16)|(5<<8)|10 = 0x0009050A */
    return 0;
}
