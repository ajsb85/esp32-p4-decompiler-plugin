/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Difference Array (range-update O(1) + reconstruct) fixture.
 *
 * The difference array technique allows O(1) range increments and O(n)
 * reconstruction:
 *   range update [l, r] += delta:  D[l] += delta; D[r+1] -= delta
 *   reconstruct A[i]:              prefix sum of D[0..i]
 *
 * Distinctive decompiler idioms:
 *   1. `D[l] += delta; D[r+1] -= delta` — single range update
 *   2. `acc += D[i]; A[i] = acc`         — prefix-sum reconstruct
 *   3. Separate update phase then scan phase (two distinct loops)
 *
 * Array A[6], initially zero.  Three range updates:
 *   [0,2] += 3  → D[0]+=3, D[3]-=3
 *   [1,4] += 2  → D[1]+=2, D[5]-=2
 *   [3,5] += 1  → D[3]+=1, D[6]-=1
 * Reconstructed: A = {3, 5, 5, 3, 3, 1}
 *
 * n    = 6
 * sum  = 3+5+5+3+3+1 = 20 = 0x14
 * xor  = 3^5^5^3^3^1 = 2
 *
 * g_result = (n << 16) | (sum << 8) | xor = 0x00061402
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Difference array ────────────────────────────────────────────────────────── */

#define DA_N  6

static int da_D[DA_N + 1]; /* difference array, one extra slot for sentinel */

static void da_range_update(int l, int r, int delta)
{
    da_D[l]     += delta;
    da_D[r + 1] -= delta;
}

/* ── Test entry point ────────────────────────────────────────────────────────── */

void test_difference_array(void)
{
    /* initialise */
    for (int i = 0; i <= DA_N; i++) da_D[i] = 0;

    /* three range updates */
    da_range_update(0, 2, 3);
    da_range_update(1, 4, 2);
    da_range_update(3, 5, 1);

    /* reconstruct and accumulate */
    uint32_t sum = 0, xor_val = 0;
    int acc = 0;
    for (int i = 0; i < DA_N; i++) {
        acc     += da_D[i];
        sum     += (uint32_t)acc;
        xor_val ^= (uint32_t)acc;
    }
    /* A = {3,5,5,3,3,1}, sum=20, xor=2 */
    g_result = ((uint32_t)DA_N << 16) | (sum << 8) | (xor_val & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_difference_array();
    for (;;);
}
