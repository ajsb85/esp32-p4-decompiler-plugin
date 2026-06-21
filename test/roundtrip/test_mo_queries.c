/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Mo's Algorithm (offline range queries) fixture.
 *
 * Mo's algorithm answers offline range queries in O((n + q) * √n) by sorting
 * queries by (block(l), r) and maintaining a sliding window [cur_l, cur_r].
 *
 * Distinctive decompiler idioms:
 *   1. Block sort: `q[a].l/MO_B < q[b].l/MO_B || (same block && q[a].r < q[b].r)`
 *   2. `if (++mo_freq[x] == 1) mo_distinct++` — add element, count new distinct
 *   3. `if (--mo_freq[x] == 0) mo_distinct--` — remove element, update count
 *   4. Expand/shrink: `while (cur_r < r) add(++cur_r)` / `while (cur_l > l) add(--cur_l)`
 *   5. Result stored by original query index: `mo_ans[q[i].idx] = mo_distinct`
 *
 * Array: [2, 3, 2, 5, 3, 2, 1]  (n=7, MO_B=3)
 * Queries (sorted by Mo's order):
 *   Q0: [0,3] → {2,3,2,5} → 3 distinct
 *   Q1: [1,4] → {3,2,5,3} → 3 distinct
 *   Q2: [2,6] → {2,5,3,2,1} → 4 distinct
 *
 * n_queries   = 3
 * sum_answers = 3+3+4 = 10 = 0x0A
 * max_answer  = 4 = 0x04
 *
 * g_result = (n_queries << 16) | (sum_answers << 8) | max_answer = 0x030A04
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MO_N 7
#define MO_Q 3
#define MO_B 3      /* block size ≈ √7 */
#define MO_MAX 8    /* max value in array + 1 */

static const int mo_arr[MO_N] = {2, 3, 2, 5, 3, 2, 1};

static int mo_freq[MO_MAX];
static int mo_distinct;
static int mo_ans[MO_Q];
static int mo_cur_l, mo_cur_r;

static void mo_add(int x) { if (++mo_freq[x] == 1) mo_distinct++; }
static void mo_remove(int x) { if (--mo_freq[x] == 0) mo_distinct--; }

typedef struct { int l, r, idx; } MoQ;
static MoQ mo_q[MO_Q];

static int mo_cmp(const MoQ *a, const MoQ *b)
{
    int ba = a->l / MO_B, bb = b->l / MO_B;
    if (ba != bb) return ba - bb;
    return (ba & 1) ? (b->r - a->r) : (a->r - b->r);
}

static void mo_sort(void)
{
    /* Simple insertion sort for 3 queries */
    for (int i = 1; i < MO_Q; i++) {
        MoQ key = mo_q[i];
        int j = i - 1;
        while (j >= 0 && mo_cmp(&mo_q[j], &key) > 0) {
            mo_q[j + 1] = mo_q[j];
            j--;
        }
        mo_q[j + 1] = key;
    }
}

void test_mo_queries(void)
{
    mo_q[0].l = 0; mo_q[0].r = 3; mo_q[0].idx = 0;
    mo_q[1].l = 1; mo_q[1].r = 4; mo_q[1].idx = 1;
    mo_q[2].l = 2; mo_q[2].r = 6; mo_q[2].idx = 2;

    mo_sort();

    mo_cur_l = 0; mo_cur_r = -1; mo_distinct = 0;

    for (int i = 0; i < MO_Q; i++) {
        int l = mo_q[i].l, r = mo_q[i].r;
        while (mo_cur_r < r) mo_add(mo_arr[++mo_cur_r]);
        while (mo_cur_l > l) mo_add(mo_arr[--mo_cur_l]);
        while (mo_cur_r > r) mo_remove(mo_arr[mo_cur_r--]);
        while (mo_cur_l < l) mo_remove(mo_arr[mo_cur_l++]);
        mo_ans[mo_q[i].idx] = mo_distinct;
    }

    int sum = 0, mx = 0;
    for (int i = 0; i < MO_Q; i++) {
        sum += mo_ans[i];
        if (mo_ans[i] > mx) mx = mo_ans[i];
    }

    g_result = ((uint32_t)MO_Q << 16)
             | ((uint32_t)sum  << 8)
             | ((uint32_t)mx & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_mo_queries();
    for (;;);
}
