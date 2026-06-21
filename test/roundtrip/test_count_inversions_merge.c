/* test_count_inversions_merge.c
 * Purpose   : Count inversions in an array using merge sort
 * Algorithm : Modified merge sort counts the number of inversions during the
 *             merge step: when a right-half element is placed before remaining
 *             left-half elements, each remaining left element forms an inversion.
 *             Total inversions = sum of such counts across all merge steps.
 * Input     : {5, 3, 8, 1, 6, 2, 7, 4} (n=8)
 * Expected  : Inversions: (5,3),(5,1),(5,2),(5,4),(3,1),(3,2),(8,1),(8,6),
 *                         (8,2),(8,7),(8,4),(6,2),(6,4),(7,4) = 14 inversions
 *             n_elem=8, inv_count=14, checksum = arr[0]+arr[n-1] = 5+4 = 9
 *             (original first and last elements, unchanged metadata)
 * g_result  = (n_elem<<16) | (inv_count<<8) | checksum
 *           = (8<<16) | (14<<8) | 9 = 0x080E09
 */

#include <stdint.h>

volatile uint32_t g_result;

#define INV_N 8

static int inv_arr[INV_N] = {5, 3, 8, 1, 6, 2, 7, 4};
static int inv_tmp[INV_N];
static int inv_orig_first;
static int inv_orig_last;

static int inv_count;

static void inv_merge_sort(int *a, int n) {
    if (n <= 1) return;
    int mid = n / 2;
    inv_merge_sort(a, mid);
    inv_merge_sort(a + mid, n - mid);

    /* Merge and count */
    int i = 0, j = mid, k = 0;
    while (i < mid && j < n) {
        if (a[i] <= a[j]) {
            inv_tmp[k++] = a[i++];
        } else {
            /* a[j] < a[i]: all remaining left elements form inversions */
            inv_count += (mid - i);
            inv_tmp[k++] = a[j++];
        }
    }
    while (i < mid) inv_tmp[k++] = a[i++];
    while (j < n)   inv_tmp[k++] = a[j++];
    for (int m = 0; m < n; m++) a[m] = inv_tmp[m];
}

void _start(void) {
    inv_orig_first = inv_arr[0];
    inv_orig_last  = inv_arr[INV_N - 1];
    inv_count = 0;

    inv_merge_sort(inv_arr, INV_N);

    int checksum = inv_orig_first + inv_orig_last; /* 5 + 4 = 9 */

    /* g_result = (n_elem<<16) | (inv_count<<8) | checksum
     *          = (8<<16) | (14<<8) | 9 = 0x080E09 */
    g_result = ((uint32_t)INV_N      << 16)
             | ((uint32_t)inv_count  <<  8)
             |  (uint32_t)checksum;
    while (1) {}
}
