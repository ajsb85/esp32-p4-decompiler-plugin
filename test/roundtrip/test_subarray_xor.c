/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Count Subarrays with Given XOR fixture.
 *
 * Counts subarrays with XOR equal to k using prefix XOR + frequency array.
 * Key identity: subarray[l..r] has XOR = prefix[r] ^ prefix[l-1].
 * Count subarrays with XOR=k: for each prefix p, count[p^k] prior occurrences.
 *
 * Distinctive decompiler idioms:
 *   1. `px ^= arr[i]; res += freq[px^k]` — accumulate count via XOR complement
 *   2. `freq[0] = 1` — seed for subarrays starting at index 0
 *   3. `freq[px]++` — record this prefix XOR frequency
 *
 * Test 1: arr={4,2,2,6,4}, k=6 → count=4
 * Test 2: arr={1,3,3,4,2,4}, k=7 → count=2
 *
 * g_result = (2<<16)|((c1+c2)<<8)|(c1^c2) = 0x00020606
 */
#include <stdint.h>

volatile uint32_t g_result;

static int count_xor_k(const int arr[], int n, int k)
{
    /* values fit in 4 bits for these test cases — avoid large zero-fill */
    static int freq[16];
    int i;
    for (i = 0; i < 16; i++) freq[i] = 0;
    freq[0] = 1;
    int px = 0, res = 0;
    for (i = 0; i < n; i++) {
        px ^= arr[i];
        res += freq[px ^ k];
        freq[px]++;
    }
    return res;
}

void test_subarray_xor(void)
{
    static const int a1[] = {4, 2, 2, 6, 4};
    static const int a2[] = {1, 3, 3, 4, 2, 4};
    int c1 = count_xor_k(a1, 5, 6);
    int c2 = count_xor_k(a2, 6, 7);
    /* c1=4, c2=2; sum=6, xor=6 */
    g_result = (2u << 16)
             | (((uint32_t)(c1 + c2)) << 8)
             | (uint32_t)(c1 ^ c2);
}

__attribute__((noreturn)) void _start(void)
{
    test_subarray_xor();
    for (;;);
}
