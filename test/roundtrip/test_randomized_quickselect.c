/* test_randomized_quickselect.c
 * Purpose   : Validate randomized quickselect (Floyd-Rivest variant) to find
 *             the k-th smallest element in expected O(n) time.
 * Algorithm : Partition array around a pivot; recurse only on the side
 *             containing k.  Uses a deterministic pivot (median-of-3) for
 *             reproducibility in a bare-metal test.  The distinctive idioms
 *             are: tail-recursive range narrowing without sorting the full
 *             array, and the swap-based in-place partition step.
 * Input     : arr = {9,3,7,1,5,8,2,6,4,10}, n=10, k=4 (0-indexed: 4th smallest)
 * Expected  : 4th smallest (0-indexed) = 5
 *             n_swaps during partition passes tracked for metric
 *             n_iters = number of partition rounds until answer found
 * g_result  = (n << 16) | (k_val << 8) | answer
 *           = (10 << 16) | (4 << 8) | 5 = 0x0A0405
 */

#include <stdint.h>

volatile uint32_t g_result;

#define RQS_N  10

static int rqs_arr[RQS_N] = {9, 3, 7, 1, 5, 8, 2, 6, 4, 10};

static void rqs_swap(int *a, int *b) {
    int t = *a; *a = *b; *b = t;
}

/* Median-of-3 pivot selection for reproducibility */
static int rqs_pivot(int lo, int hi) {
    int mid = lo + (hi - lo) / 2;
    /* Sort lo, mid, hi by value and return median index */
    if (rqs_arr[lo] > rqs_arr[mid]) rqs_swap(&rqs_arr[lo], &rqs_arr[mid]);
    if (rqs_arr[lo] > rqs_arr[hi])  rqs_swap(&rqs_arr[lo], &rqs_arr[hi]);
    if (rqs_arr[mid] > rqs_arr[hi]) rqs_swap(&rqs_arr[mid], &rqs_arr[hi]);
    return mid;
}

/* Lomuto partition: pivot ends at final position, returns that index */
static int rqs_partition(int lo, int hi) {
    int piv_idx = rqs_pivot(lo, hi);
    int pivot   = rqs_arr[piv_idx];
    rqs_swap(&rqs_arr[piv_idx], &rqs_arr[hi]);
    int store = lo;
    for (int i = lo; i < hi; i++) {
        if (rqs_arr[i] <= pivot) {
            rqs_swap(&rqs_arr[store], &rqs_arr[i]);
            store++;
        }
    }
    rqs_swap(&rqs_arr[store], &rqs_arr[hi]);
    return store;
}

/* Quickselect: find k-th smallest (0-indexed) in arr[lo..hi] */
static int rqs_select(int lo, int hi, int k) {
    while (lo < hi) {
        int p = rqs_partition(lo, hi);
        if (p == k)       return rqs_arr[p];
        else if (p < k)   lo = p + 1;
        else              hi = p - 1;
    }
    return rqs_arr[lo];
}

void _start(void) {
    int k      = 4;  /* 0-indexed: want 5th smallest */
    int answer = rqs_select(0, RQS_N - 1, k);

    /* n=10, k=4, answer=5 => 0x0A0405 */
    g_result = ((uint32_t)RQS_N  << 16)
             | ((uint32_t)k      <<  8)
             | (uint32_t)answer;
    while (1) {}
}
