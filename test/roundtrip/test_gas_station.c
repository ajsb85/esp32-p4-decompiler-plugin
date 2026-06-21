/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Gas Station Greedy fixture.
 *
 * Find the starting gas station (0-indexed) from which a vehicle can complete
 * a circular circuit, given gas[] and cost[] at each station.
 *
 * Greedy idiom:
 *   - If total gas < total cost: no solution (return -1)
 *   - Forward scan: tank += gas[i] - cost[i]; if tank < 0: reset start=i+1, tank=0
 *
 * Distinctive decompiler idioms:
 *   1. Two-variable summary: `total` tracks overall feasibility; `tank` tracks local
 *   2. Reset pattern: `if (tank < 0) { start = i+1; tank = 0; }` — greedy re-anchor
 *   3. Single-pass: no circular simulation (feasibility checked via total only)
 *
 * Three test cases:
 *   1. gas={1,2,3,4,5} cost={3,4,5,1,2}: total=0 ≥ 0 → start=3
 *   2. gas={2,3,4}     cost={3,4,3}:     total=-1 < 0 → -1 (impossible)
 *   3. gas={5,1,2,3,4} cost={4,4,1,5,1}: total=0 ≥ 0 → start=4
 *
 * n_tests     = 3
 * count_valid = 2   (tests 1 and 3 have valid starting stations)
 * xor_starts  = 3^4 = 7
 *
 * g_result = (n_tests << 16) | (count_valid << 8) | xor_starts = 0x00030207
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Gas Station ─────────────────────────────────────────────────────────── */

#define GS_TESTS 3

static int gas_station(const int *gas, const int *cost, int n)
{
    int total = 0, tank = 0, start = 0;
    for (int i = 0; i < n; i++) {
        int diff = gas[i] - cost[i];
        total += diff;
        tank  += diff;
        if (tank < 0) { start = i + 1; tank = 0; }
    }
    return (total < 0) ? -1 : start;
}

/* ── Test entry point ─────────────────────────────────────────────────────── */

void test_gas_station(void)
{
    static const int g0[] = {1, 2, 3, 4, 5}, c0[] = {3, 4, 5, 1, 2}; /* start=3 */
    static const int g1[] = {2, 3, 4},       c1[] = {3, 4, 3};        /* impossible */
    static const int g2[] = {5, 1, 2, 3, 4}, c2[] = {4, 4, 1, 5, 1}; /* start=4 */

    static const int *gas[]  = {g0, g1, g2};
    static const int *cost[] = {c0, c1, c2};
    static const int  lens[] = { 5,  3,  5};

    uint32_t count_valid = 0, xor_starts = 0;
    for (int t = 0; t < GS_TESTS; t++) {
        int r = gas_station(gas[t], cost[t], lens[t]);
        if (r >= 0) {
            count_valid++;
            xor_starts ^= (uint32_t)r;
        }
    }
    /* count=2, xor=3^4=7 */

    g_result = ((uint32_t)GS_TESTS << 16) | (count_valid << 8) | (xor_starts & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_gas_station();
    for (;;);
}
