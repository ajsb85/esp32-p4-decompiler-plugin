/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Viterbi Algorithm (HMM Decoding) fixture.
 *
 * The Viterbi algorithm finds the most probable hidden state sequence in an
 * HMM given an observation sequence.  It uses DP similar to forward algorithm
 * but keeps argmax (backpointer) instead of sum.
 *
 * Distinctive decompiler idioms:
 *   1. `dp[t][s] = max_ps(dp[t-1][ps] * trans[ps][s]) * emit[s][obs[t]]` — Viterbi recurrence
 *   2. `bt[t][s] = argmax_ps(dp[t-1][ps] * trans[ps][s])` — backpointer for traceback
 *   3. `for (s=1; s<S; s++) if (dp[T-1][s] > dp[T-1][best]) best=s` — find best final state
 *   4. `path[t] = bt[t+1][path[t+1]]` — traceback from final state to initial
 *   5. Integer-scaled probabilities (no floating-point) for embedded targets
 *
 * HMM parameters (2 states, integer probabilities ×10):
 *   pi   = {6, 4}     (60% state 0, 40% state 1)
 *   trans[0] = {7, 3} (70% stay in 0, 30% go to 1)
 *   trans[1] = {4, 6} (40% go to 0, 60% stay in 1)
 *   emit[0]  = {8, 2} (state 0 emits obs-0 with 80%, obs-1 with 20%)
 *   emit[1]  = {3, 7} (state 1 emits obs-0 with 30%, obs-1 with 70%)
 *
 * Observation sequence: [0, 1, 0, 1]  (T=4 steps)
 * Viterbi path: [0, 0, 0, 1]  (path_sum=1)
 * Best final state: 1 (state 1 at t=3)
 *
 * VT_T       = 4  = 0x04
 * path_sum   = 1  = 0x01
 * best_state = 1  = 0x02  (encoded as best_state+1 to avoid zero byte)
 *
 * g_result = (VT_T << 16) | (path_sum << 8) | (best_state+1) = 0x040102
 */
#include <stdint.h>

volatile uint32_t g_result;

#define VT_S 2
#define VT_T 4

static const int vt_pi[VT_S]              = {6, 4};
static const int vt_trans[VT_S][VT_S]     = {{7,3},{4,6}};
static const int vt_emit[VT_S][2]         = {{8,2},{3,7}};
static const int vt_obs[VT_T]             = {0, 1, 0, 1};

static int vt_dp[VT_T][VT_S];
static int vt_bt[VT_T][VT_S];

void test_viterbi(void)
{
    for (int s = 0; s < VT_S; s++) {
        vt_dp[0][s] = vt_pi[s] * vt_emit[s][vt_obs[0]];
        vt_bt[0][s] = -1;
    }

    for (int t = 1; t < VT_T; t++) {
        for (int s = 0; s < VT_S; s++) {
            int best = -1, best_p = -1;
            for (int ps = 0; ps < VT_S; ps++) {
                int p = vt_dp[t-1][ps] * vt_trans[ps][s];
                if (p > best_p) { best_p = p; best = ps; }
            }
            vt_dp[t][s] = best_p * vt_emit[s][vt_obs[t]];
            vt_bt[t][s] = best;
        }
    }

    int best_s = 0;
    for (int s = 1; s < VT_S; s++)
        if (vt_dp[VT_T-1][s] > vt_dp[VT_T-1][best_s]) best_s = s;

    int path[VT_T];
    path[VT_T - 1] = best_s;
    for (int t = VT_T - 2; t >= 0; t--)
        path[t] = vt_bt[t + 1][path[t + 1]];

    int path_sum = 0;
    for (int t = 0; t < VT_T; t++) path_sum += path[t];
    /* path=[0,0,0,1], path_sum=1, best_s=1 */

    g_result = ((uint32_t)VT_T     << 16)
             | ((uint32_t)path_sum << 8)
             | ((uint32_t)(best_s + 1) & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_viterbi();
    for (;;);
}
