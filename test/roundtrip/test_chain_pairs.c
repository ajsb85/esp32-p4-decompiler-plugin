/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Longest Chain of Pairs fixture.
 *
 * Finds the longest chain of pairs (a,b) where b_i < a_{i+1}, using greedy:
 * sort by end value (b), greedily select pairs whose start > last selected end.
 *
 * Distinctive decompiler idioms:
 *   1. Insertion sort by `pb[j]` — sort pairs by end value
 *   2. `if(pa[i]>last_b){ chain++; last_b=pb[i]; xb^=pb[i]; }` — greedy select
 *   3. Chain starts with first pair (always selected); last_b tracks end
 *
 * Pairs: (5,24),(15,25),(15,28),(27,40),(50,60) sorted by b
 * Chain: (5,24)→(27,40)→(50,60) → length 3
 * xor of selected b values: 24^40^60=12
 *
 * g_result = (n_pairs<<16)|(chain_len<<8)|(xor_b_selected&0xFF) = 0x0005030C
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_chain_pairs(void)
{
    int pa[5] = {5, 15, 27, 50, 15};
    int pb[5] = {24, 25, 40, 60, 28};
    int n = 5;

    /* Insertion sort by b (end value) */
    for (int i = 1; i < n; i++) {
        int ka = pa[i], kb = pb[i], j = i - 1;
        while (j >= 0 && pb[j] > kb) {
            pa[j+1] = pa[j]; pb[j+1] = pb[j]; j--;
        }
        pa[j+1] = ka; pb[j+1] = kb;
    }
    /* Sorted: (5,24),(15,25),(15,28),(27,40),(50,60) */

    /* Greedy: always select first pair */
    int chain = 1, last_b = pb[0];
    uint32_t xb = (uint32_t)pb[0];

    for (int i = 1; i < n; i++) {
        if (pa[i] > last_b) {
            chain++;
            xb ^= (uint32_t)pb[i];
            last_b = pb[i];
        }
    }
    /* chain=3, xb=24^40^60=12=0x0C */
    g_result = ((uint32_t)n << 16)
             | ((uint32_t)chain << 8)
             | (xb & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_chain_pairs();
    for (;;);
}
