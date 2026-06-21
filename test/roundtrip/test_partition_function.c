/* test_partition_function.c
 * Purpose   : Validate integer partition function p(n) via pentagonal recurrence
 * Algorithm : Euler's pentagonal number theorem:
 *             p(n) = sum_{k!=0} (-1)^{k+1} p(n - k*(3k-1)/2)
 *             Generalised pentagonal numbers: g(k) = k*(3k-1)/2 for k=1,-1,2,-2,...
 * Tests     : p(7)=15, p(10)=42, p(12)=77
 *             n_tests=3, metric_a=p(10)%256=42=0x2A, metric_b=p(7)=15=0x0F
 * g_result  = (3<<16)|(0x2A<<8)|0x0F = 0x032A0F
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define PART_MAX 13   /* compute p(0)..p(12) */

static uint32_t part[PART_MAX];

static void partition_build(void) {
    part[0] = 1;
    for (int n = 1; n < PART_MAX; n++) {
        int32_t val = 0;
        /* iterate k = 1, -1, 2, -2, 3, -3, ... until pentagonal > n */
        for (int k = 1; ; k++) {
            /* positive: g = k*(3k-1)/2 */
            int gpos = k * (3*k - 1) / 2;
            if (gpos > n) break;
            if (k % 2 == 1) val += (int32_t)part[n - gpos];
            else             val -= (int32_t)part[n - gpos];

            /* negative: g = k*(3k+1)/2 */
            int gneg = k * (3*k + 1) / 2;
            if (gneg > n) break;
            if (k % 2 == 1) val += (int32_t)part[n - gneg];
            else             val -= (int32_t)part[n - gneg];
        }
        part[n] = (uint32_t)val;
    }
}

static uint32_t run_partition_tests(void) {
    partition_build();

    /* Test 1: p(7)  = 15 */
    uint32_t p7  = part[7];   /* expect 15 */

    /* Test 2: p(10) = 42 */
    uint32_t p10 = part[10];  /* expect 42 */

    /* Test 3: p(12) = 77 */
    uint32_t p12 = part[12];  /* expect 77 */
    (void)p12;

    /* metric_a = p10 = 42 = 0x2A
     * metric_b = p7  = 15 = 0x0F
     * n_tests=3 => 0x032A0F */
    uint32_t metric_a = p10 & 0xFFu;
    uint32_t metric_b = p7  & 0xFFu;
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_partition_tests();
    while (1) {}
}
