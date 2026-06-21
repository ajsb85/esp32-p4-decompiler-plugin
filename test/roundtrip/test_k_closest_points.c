#include <stdint.h>
#include <stdlib.h>

/* K closest points to origin (0,0), ranked by Euclidean distance squared.
 * Sort by x²+y², return first K.
 * g_result encodes (n, sum_dist2_of_k_closest, k). */

typedef struct { int x, y; } Point;

static int dist_sq(const Point *p) { return p->x * p->x + p->y * p->y; }

static int cmp_pts(const void *a, const void *b) {
    return dist_sq((const Point *)a) - dist_sq((const Point *)b);
}

volatile uint32_t g_result;

void test_k_closest_points(void) {
    Point pts[] = {{1,3},{-2,2},{5,8},{0,1}};
    int n = 4, k = 2;
    qsort(pts, (size_t)n, sizeof(Point), cmp_pts);
    int sd = 0;
    for (int i = 0; i < k; i++) sd += dist_sq(&pts[i]);
    /* k=2 closest: (0,1)[d²=1] + (-2,2)[d²=8] → sd=9 */
    g_result = ((uint32_t)n << 16) | ((uint32_t)sd << 8) | (uint32_t)k; /* 0x00040902 */
}

__attribute__((noreturn)) void _start(void) {
    test_k_closest_points();
    for (;;);
}
