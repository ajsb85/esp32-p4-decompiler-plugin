/*
 * test_halfplane_intersection.c
 * Half-plane intersection: check whether a query point lies inside the
 * intersection of N half-planes (ax + by <= c).
 * Uses integer arithmetic only — no FP, no stdlib.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

typedef struct {
    int32_t a, b, c; /* half-plane: a*x + b*y <= c */
} HalfPlane;

/* Returns 1 if point (px, py) satisfies all half-planes */
static int hpi_contains(const HalfPlane *hp, int n, int32_t px, int32_t py) {
    for (int i = 0; i < n; i++) {
        /* check a*px + b*py <= c */
        int32_t val = hp[i].a * px + hp[i].b * py;
        if (val > hp[i].c)
            return 0;
    }
    return 1;
}

/*
 * Compute the "depth" of a point inside the half-plane set:
 * number of constraints it satisfies.
 */
static int hpi_depth(const HalfPlane *hp, int n, int32_t px, int32_t py) {
    int cnt = 0;
    for (int i = 0; i < n; i++) {
        if (hp[i].a * px + hp[i].b * py <= hp[i].c)
            cnt++;
    }
    return cnt;
}

/*
 * Scan a grid of candidate points and count how many are strictly inside
 * all half-planes.
 */
static int hpi_grid_count(const HalfPlane *hp, int n,
                           int32_t x0, int32_t x1, int32_t dx,
                           int32_t y0, int32_t y1, int32_t dy) {
    int cnt = 0;
    for (int32_t x = x0; x <= x1; x += dx) {
        for (int32_t y = y0; y <= y1; y += dy) {
            if (hpi_contains(hp, n, x, y))
                cnt++;
        }
    }
    return cnt;
}

static uint32_t run_halfplane_tests(void) {
    /*
     * Test 1: unit square half-planes (x>=0, x<=4, y>=0, y<=4)
     * represented as: -x<=0, x<=4, -y<=0, y<=4
     * Grid 0..4 step 1 (5x5=25 points) — all inside → 25
     */
    HalfPlane sq[] = {
        { -1,  0,  0 }, /* -x <= 0  i.e. x >= 0 */
        {  1,  0,  4 }, /* x  <= 4  */
        {  0, -1,  0 }, /* -y <= 0  i.e. y >= 0 */
        {  0,  1,  4 }, /* y  <= 4  */
    };
    int c1 = hpi_grid_count(sq, 4, 0, 4, 1, 0, 4, 1); /* expected 25 */
    (void)c1;

    /*
     * Test 2: add diagonal constraint x+y<=5
     * Points (x,y) with x+y>5 are cut: (2,4),(3,3),(3,4),(4,2),(4,3),(4,4) → 6 cut
     * Remaining = 25 - 6 = 19
     */
    HalfPlane tri[] = {
        { -1,  0,  0 },
        {  1,  0,  4 },
        {  0, -1,  0 },
        {  0,  1,  4 },
        {  1,  1,  5 }, /* x + y <= 5 */
    };
    int c2 = hpi_grid_count(tri, 5, 0, 4, 1, 0, 4, 1); /* expected 19 */

    /*
     * Test 3: depth query — point (2,2) satisfies all 5 constraints above.
     */
    int d3 = hpi_depth(tri, 5, 2, 2); /* expected 5 */

    /*
     * Pack: n_tests=3, metric_a=c2 (19=0x13), metric_b=d3 (5=0x05)
     * Bytes: 0x03, 0x13, 0x05 — all non-zero and distinct.
     */
    uint32_t metric_a = (uint32_t)(c2 & 0xFF); /* 19 = 0x13 */
    uint32_t metric_b = (uint32_t)(d3 & 0xFF); /* 5  = 0x05 */
    return (3u << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_halfplane_tests();
    while (1) {}
}
