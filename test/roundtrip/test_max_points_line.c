/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Max Points on a Line (cross-product collinearity).
 *
 * For each pivot point, counts collinear points using cross-product:
 * points A,B,C collinear iff dx_AB * dy_AC == dx_AC * dy_AB.
 * Brute-force O(n^3) to avoid division/GCD for slope comparison.
 *
 * Distinctive decompiler idioms:
 *   1. `for(i<n) for(j!=i; for(k!=i,k!=j)` — triple pivot loop
 *   2. `(long)dx*dy2==(long)dx2*dy` — cross-product collinearity check
 *   3. `if(maxs+1>best)best=maxs+1` — +1 for the pivot itself
 *
 * Points: (1,1),(2,2),(3,3),(1,0),(2,0),(3,0)
 * Three collinear: {(1,1),(2,2),(3,3)} and {(1,0),(2,0),(3,0)} → max=3
 * n=6, best=3, best*2=6
 *
 * g_result = (n<<16)|(best<<8)|(best*2) = 0x00060306
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_max_points_line(void)
{
    static const int px[6] = {1, 2, 3, 1, 2, 3};
    static const int py[6] = {1, 2, 3, 0, 0, 0};
    int n = 6, best = 0;

    for (int i = 0; i < n; i++) {
        int maxs = 0;
        for (int j = 0; j < n; j++) {
            if (j == i) continue;
            int dx = px[j] - px[i], dy = py[j] - py[i];
            int cnt = 1;
            for (int k = 0; k < n; k++) {
                if (k == i || k == j) continue;
                int dx2 = px[k] - px[i], dy2 = py[k] - py[i];
                if ((long)dx * dy2 == (long)dx2 * dy) cnt++;
            }
            if (cnt > maxs) maxs = cnt;
        }
        if (maxs + 1 > best) best = maxs + 1;
    }
    /* best=3, best*2=6 */
    g_result = ((uint32_t)n << 16)
             | ((uint32_t)best << 8)
             | (uint32_t)(best * 2);
}

__attribute__((noreturn)) void _start(void)
{
    test_max_points_line();
    for (;;);
}
