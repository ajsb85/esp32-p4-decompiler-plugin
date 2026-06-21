/* test_z_function.c
 * Purpose   : Validate Z-algorithm (Z-function) for string matching
 * Algorithm : For string s[0..n-1], Z[i] = length of the longest substring
 *             starting at s[i] that matches a prefix of s.  Uses the O(n)
 *             window-extension algorithm with [l,r] tracking.
 * Input     : "aabxaa" (n=6)
 * Expected  : Z[] = {0, 1, 0, 0, 2, 1}
 *             sum_z = 0+1+0+0+2+1 = 4, max_z = 2, n = 6
 * g_result  = (n << 16) | (sum_z << 8) | max_z
 *           = (6 << 16) | (4 << 8) | 2 = 0x060402
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define ZF_N 6
static const char zf_s[ZF_N + 1] = "aabxaa";
static int zf_z[ZF_N];

static void zf_compute(void) {
    int n = ZF_N;
    int l = 0, r = 0;
    zf_z[0] = 0;
    for (int i = 1; i < n; i++) {
        int zi = 0;
        if (i < r) {
            zi = zf_z[i - l];
            if (zi > r - i) zi = r - i;
        }
        while (i + zi < n && zf_s[zi] == zf_s[i + zi]) zi++;
        zf_z[i] = zi;
        if (i + zi > r) { l = i; r = i + zi; }
    }
}

void _start(void) {
    zf_compute();

    int sum_z = 0, max_z = 0;
    for (int i = 1; i < ZF_N; i++) {
        sum_z += zf_z[i];
        if (zf_z[i] > max_z) max_z = zf_z[i];
    }

    g_result = ((uint32_t)ZF_N << 16) | ((uint32_t)sum_z << 8) | (uint32_t)max_z;
    while (1) {}
}
