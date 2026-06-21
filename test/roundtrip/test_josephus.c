/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Josephus problem (recurrence) fixture.
 *
 * Find the surviving position in the Josephus problem: n people in a circle,
 * every k-th person is eliminated.  O(n) recurrence:
 *
 *   J(1) = 0
 *   J(i) = (J(i-1) + k) % i    for i = 2..n
 *
 * Survivor is J(n) (0-indexed), or J(n)+1 (1-indexed).
 *
 * Distinctive decompiler idiom:
 *   pos = 0;
 *   for (i = 2; i <= n; i++) pos = (pos + k) % i;
 *   survivor = pos + 1;
 *
 * Test 1: n=10, k=3
 *   J(1)=0
 *   J(2)=(0+3)%2=1
 *   J(3)=(1+3)%3=1
 *   J(4)=(1+3)%4=0
 *   J(5)=(0+3)%5=3
 *   J(6)=(3+3)%6=0
 *   J(7)=(0+3)%7=3
 *   J(8)=(3+3)%8=6
 *   J(9)=(6+3)%9=0
 *   J(10)=(0+3)%10=3  → survivor=4 (1-indexed)
 *
 * Test 2: n=7, k=2
 *   J(1)=0 J(2)=0 J(3)=2 J(4)=0 J(5)=2 J(6)=4 J(7)=6 → survivor=7 (1-indexed)
 *
 * Test 3: n=12, k=4
 *   J(1)=0 J(2)=0 J(3)=1 J(4)=1 J(5)=0 J(6)=4 J(7)=1 J(8)=5
 *   J(9)=0 J(10)=4 J(11)=8 J(12)=0 → survivor=1 (1-indexed)
 *
 * Survivors: 4, 7, 1
 * Sum = 4+7+1 = 12 = 0x0C
 * XOR = 4^7^1 = (4^7)^1 = 3^1 = 2
 *
 * g_result = (n1 << 16) | (sum << 8) | xor
 *          = (10 << 16) | (12 << 8) | 2
 *          = 0x000A0C02
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Josephus ─────────────────────────────────────────────────────────────── */

static int josephus(int n, int k)
{
    int pos = 0;
    for (int i = 2; i <= n; i++)
        pos = (pos + k) % i;
    return pos + 1;   /* 1-indexed survivor */
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_josephus(void)
{
    static const int ns[] = {10,  7, 12};
    static const int ks[] = { 3,  2,  4};

    uint32_t sum_s = 0, xor_s = 0;
    for (int t = 0; t < 3; t++) {
        uint32_t s = (uint32_t)josephus(ns[t], ks[t]);
        sum_s += s;
        xor_s ^= s;
    }

    /* sum=12, xor=2, n[0]=10 → 0x000A0C02 */
    g_result = ((uint32_t)ns[0] << 16)
             | (sum_s << 8)
             | (xor_s & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_josephus();
    for (;;);
}
