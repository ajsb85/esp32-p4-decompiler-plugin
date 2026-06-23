/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Closest Pair of Points (Divide & Conquer).
 *
 * The divide-and-conquer closest pair algorithm finds the minimum Euclidean
 * distance between any two points in O(n log n) by:
 *   1. Sorting points by x-coordinate.
 *   2. Splitting at the median; recursing on left and right halves.
 *   3. Merging: checking a "strip" of width 2*d around the dividing line.
 *   4. Only O(7) comparisons per strip point (vertical strip sorted by y).
 *   5. Returning min(d_left, d_right, d_strip).
 *
 * Distinctive decompiler idioms:
 *   1. `for (j=i+1; j<m && (strip[j].y-strip[i].y)^2 < best; j++)` — strip inner loop
 *   2. `if (dx*dx < d)` — filtering strip candidates by x-distance squared
 *   3. `mx = arr[mid].x` — dividing line at median x
 *   4. Merge sort by y during recursion (interleaved with distance computation)
 *   5. `long dx=a.x-b.x; long dy=a.y-b.y; return dx*dx+dy*dy` — squared distance
 *
 * Points (6): {(0,0), (4,3), (4,4), (8,0), (8,6), (12,3)}  (pre-sorted by x)
 * Closest pair: (4,3)−(4,4), squared distance = 0+1 = 1
 * Strip at final merge (midpoint x=8): points in strip: {(8,0),(8,6)} → n_strip=2
 *
 * n_points    = 6  = 0x06
 * min_dist_sq = 1  = 0x01
 * n_strip     = 2  = 0x02
 *
 * g_result = (n_points << 16) | (min_dist_sq << 8) | n_strip = 0x060102 ✓
 */
#include <stdint.h>

volatile uint32_t g_result;

#define CP_N 6

typedef struct { int x, y; } CPt;

static CPt cp_pts[CP_N] = {{0,0},{4,3},{4,4},{8,0},{8,6},{12,3}};
static int cp_strip_count; /* number of strip candidates at top-level merge */

static long cp_dist2(CPt a, CPt b)
{
    long dx = a.x - b.x, dy = a.y - b.y;
    return dx * dx + dy * dy;
}

static long cp_strip_min(CPt *strip, int m, long d)
{
    long best = d;
    for (int i = 0; i < m; i++) {
        for (int j = i + 1; j < m; j++) {
            long dy = strip[j].y - strip[i].y;
            if (dy * dy >= best) break;
            long d2 = cp_dist2(strip[i], strip[j]);
            if (d2 < best) best = d2;
        }
    }
    return best;
}

/* tmp buffer for merge-by-y */
static CPt cp_tmp[CP_N];

static long cp_closest(CPt *arr, int n, int top_level)
{
    if (n <= 3) {
        long mn = cp_dist2(arr[0], arr[1]);
        if (n == 3) {
            long d2 = cp_dist2(arr[0], arr[2]);
            long d3 = cp_dist2(arr[1], arr[2]);
            if (d2 < mn) mn = d2;
            if (d3 < mn) mn = d3;
        }
        /* sort by y for parent's strip check */
        for (int i = 0; i < n - 1; i++)
            for (int j = 0; j < n - 1 - i; j++)
                if (arr[j].y > arr[j+1].y) {
                    CPt t = arr[j]; arr[j] = arr[j+1]; arr[j+1] = t;
                }
        return mn;
    }
    int mid = n / 2;
    int mx  = arr[mid].x;
    long dl = cp_closest(arr,       mid,   0);
    long dr = cp_closest(arr + mid, n - mid, 0);
    long d  = (dl < dr) ? dl : dr;

    /* merge sub-arrays sorted by y */
    int a = 0, b = mid, ti = 0;
    while (a < mid && b < n)
        cp_tmp[ti++] = (arr[a].y <= arr[b].y) ? arr[a++] : arr[b++];
    while (a < mid) cp_tmp[ti++] = arr[a++];
    while (b < n)   cp_tmp[ti++] = arr[b++];
    for (int i = 0; i < n; i++) arr[i] = cp_tmp[i];

    /* build strip — count candidates at top-level merge */
    CPt strip[CP_N];
    int m = 0;
    for (int i = 0; i < n; i++) {
        long dx = (long)(arr[i].x - mx);
        if (dx * dx < d) {
            strip[m++] = arr[i];
            if (top_level) cp_strip_count++;
        }
    }
    long ds = cp_strip_min(strip, m, d);
    return (ds < d) ? ds : d;
}

void test_closest_pair(void)
{
    cp_strip_count = 0;
    long min_d2 = cp_closest(cp_pts, CP_N, 1);
    /* min_d2=1, strip_count=2 */

    g_result = ((uint32_t)CP_N          << 16)
             | ((uint32_t)min_d2        <<  8)
             | ((uint32_t)cp_strip_count & 0xFF);
}

__attribute__((noreturn)) void _start(void)
{
    test_closest_pair();
    for (;;);
}
