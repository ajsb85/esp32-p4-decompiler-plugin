/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Fibonacci memoization (top-down DP) round-trip fixture.
 *
 * Top-down memoized Fibonacci: compute fib(n) for n = 0..9 via a recursive
 * function that stores results in a cache table to avoid redundant computation.
 *
 * fib_cache[] is initialized to -1 (uncomputed).  On each call:
 *   1. If n <= 1, return n directly.
 *   2. If fib_cache[n] >= 0, return cached value.
 *   3. Otherwise compute, store, and return fib(n-1) + fib(n-2).
 *
 * fib(0..9) = {0, 1, 1, 2, 3, 5, 8, 13, 21, 34}
 *   fib(9)    = 34  = 0x22
 *   count     = 10
 *   xor_all   = 0^1^1^2^3^5^8^13^21^34 = 54 = 0x36
 *
 * g_result = (count << 16) | (fib(9) << 8) | xor_all = 0x000A2236
 *
 * Recognizable decompiler idioms:
 *   if (fib_cache[n] >= 0) return fib_cache[n];   ← memoization cache check
 *   fib_cache[n] = fib(n-1) + fib(n-2);           ← store before return
 *   return fib_cache[n];
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Memoization cache ────────────────────────────────────────────────────── */

#define FIB_MAX 16

static int fib_cache[FIB_MAX];

static int fib(int n)
{
    if (n <= 1)
        return n;
    if (fib_cache[n] >= 0)
        return fib_cache[n];
    fib_cache[n] = fib(n - 1) + fib(n - 2);
    return fib_cache[n];
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_fib_memo(void)
{
    for (int i = 0; i < FIB_MAX; i++)
        fib_cache[i] = -1;

    const int count = 10;
    uint32_t xor_all = 0;
    for (int i = 0; i < count; i++)
        xor_all ^= (uint32_t)fib(i);

    g_result = ((uint32_t)count << 16)
             | ((uint32_t)fib(9) << 8)
             | (xor_all & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_fib_memo();
    for (;;);
}
