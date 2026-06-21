/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Parallel Binary Search fixture.
 *
 * Answers Q queries simultaneously by maintaining a binary search range
 * [lo[q], hi[q]] for each query and narrowing all ranges in a single sweep.
 * Useful when the check function (prefix sum here) is costly and reusable.
 *
 * Distinctive decompiler idioms:
 *   1. Outer loop: `for (iter=0; iter<LOG_N; iter++)` — log(N) passes
 *   2. Inner double loop: sweep i=0..N-1, check all queries with mid==i
 *   3. `mid = (lo[q]+hi[q])/2; if (mid==i) { check; narrow }` — per-query mid
 *   4. `if (psum >= thresh[q]) hi[q]=mid-1; else lo[q]=mid+1` — classic binary search
 *   5. Final answers: `ans[q] = lo[q]` (converged lower bound)
 *
 * Array: [1,3,2,4,1,5] (n=6)
 * Prefix sums: [1,4,6,10,11,16]
 * Queries (find first index where prefix_sum >= threshold):
 *   Q0: threshold=5  → index 2 (prefix[2]=6 ≥ 5)
 *   Q1: threshold=11 → index 4 (prefix[4]=11 ≥ 11)
 *   Q2: threshold=3  → index 1 (prefix[1]=4 ≥ 3)
 * Sum of answers = 2+4+1 = 7
 *
 * n       = 6  = 0x06
 * sum_ans = 7  = 0x07
 * ans[0]  = 2  = 0x02
 *
 * g_result = (n << 16) | (sum_ans << 8) | ans[0] = 0x060702
 */
#include <stdint.h>

volatile uint32_t g_result;

#define PBS_N   6
#define PBS_Q   3
#define PBS_LOG 4   /* ceil(log2(6)) + 1 */

static const int pbs_a[PBS_N]   = {1, 3, 2, 4, 1, 5};
static const int pbs_thr[PBS_Q] = {5, 11, 3};

static int pbs_lo[PBS_Q], pbs_hi[PBS_Q];

void test_parallel_bsearch(void)
{
    for (int q = 0; q < PBS_Q; q++) { pbs_lo[q] = 0; pbs_hi[q] = PBS_N - 1; }

    for (int iter = 0; iter < PBS_LOG; iter++) {
        int psum = 0;
        for (int i = 0; i < PBS_N; i++) {
            psum += pbs_a[i];
            for (int q = 0; q < PBS_Q; q++) {
                if (pbs_lo[q] > pbs_hi[q]) continue;
                int mid = (pbs_lo[q] + pbs_hi[q]) / 2;
                if (mid == i) {
                    if (psum >= pbs_thr[q]) pbs_hi[q] = mid - 1;
                    else                    pbs_lo[q] = mid + 1;
                }
            }
        }
    }

    /* Answers: lo[q] after convergence */
    int sum = 0;
    for (int q = 0; q < PBS_Q; q++) sum += pbs_lo[q];

    g_result = ((uint32_t)PBS_N       << 16)
             | ((uint32_t)sum         << 8)
             | ((uint32_t)pbs_lo[0]   & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_parallel_bsearch();
    for (;;);
}
