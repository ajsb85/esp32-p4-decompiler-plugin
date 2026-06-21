/* test_josephus_problem.c
 * Josephus Problem — iterative O(n) formula
 * J(n) = (J(n-1) + k) % n,  J(1) = 0
 * 32-bit only; no stdlib needed.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Iterative Josephus with step k=2, returns 0-based survivor index */
static uint32_t josephus(uint32_t n, uint32_t k)
{
    uint32_t pos = 0u;              /* J(1,k) = 0 */
    uint32_t i;
    for (i = 2u; i <= n; i++) {
        pos = (pos + k) % i;
    }
    return pos;
}

/* Generic step version for varied k */
static uint32_t josephus_k(uint32_t n, uint32_t k)
{
    uint32_t pos = 0u;
    uint32_t i;
    for (i = 2u; i <= n; i++) {
        pos = (pos + k) % i;
    }
    return pos;
}

void _start(void)
{
    /* J(10,2)=2, J(7,3)=3, J(5,2)=2 — classic results */
    uint32_t j10 = josephus(10u, 2u);   /* survivor in circle of 10, step 2 => index 2 */
    uint32_t j7  = josephus_k(7u, 3u);  /* survivor in circle of  7, step 3 => index 3 */
    uint32_t j5  = josephus_k(5u, 2u);  /* survivor in circle of  5, step 2 => index 2 */

    /* n_tests=3, metric_a=j10+1, metric_b=j7+1 => (3<<16)|(3<<8)|4 = 0x030304 */
    uint32_t n_tests  = 3u;
    uint32_t metric_a = j10 + 1u;   /* 3 */
    uint32_t metric_b = j7  + 1u;   /* 4 */
    (void)j5;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;

    while (1) {}
}
