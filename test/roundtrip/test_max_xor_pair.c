/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Maximum XOR of Pairs (brute-force O(n^2)).
 *
 * Finds the maximum and second-maximum XOR value across all array pairs.
 * Brute-force: try every (i,j) pair with i<j, track top-2 XOR values.
 *
 * Distinctive decompiler idioms:
 *   1. `for(i<n) for(j=i+1;j<n)` — upper-triangle pair enumeration
 *   2. `v=arr[i]^arr[j]; if(v>mx){mx2=mx;mx=v;}` — rolling top-2 XOR
 *   3. `g_result = (n<<16)|(max<<8)|second_max` — encode two extremes
 *
 * Array: {3,10,5,25,2,8}, n=6
 * Max XOR: 5^25=28, Second: 25^2=27
 *
 * g_result = (6<<16)|(28<<8)|27 = 0x00061C1B
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_max_xor_pair(void)
{
    static const int arr[6] = {3, 10, 5, 25, 2, 8};
    int n = 6, mx = 0, mx2 = 0;

    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            int v = arr[i] ^ arr[j];
            if (v > mx) { mx2 = mx; mx = v; }
            else if (v > mx2) mx2 = v;
        }
    }
    /* mx=28=0x1C, mx2=27=0x1B */
    g_result = ((uint32_t)n << 16)
             | ((uint32_t)mx << 8)
             | (uint32_t)mx2;
}

__attribute__((noreturn)) void _start(void)
{
    test_max_xor_pair();
    for (;;);
}
