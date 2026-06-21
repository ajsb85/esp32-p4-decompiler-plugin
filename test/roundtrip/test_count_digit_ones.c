/*
 * test_count_digit_ones.c — count total 1-digits in all numbers 1..n.
 *
 * For each digit position pos (1, 10, 100, ...):
 *   higher = n / (pos*10)
 *   current = (n / pos) % 10
 *   lower = n % pos
 *   if current > 1: count += (higher+1)*pos
 *   if current == 1: count += higher*pos + lower + 1
 *   if current == 0: count += higher*pos
 *
 * Tests: n=13→6, n=50→15, n=100→21
 * n_tests=3, sum=42=0x2A, xor=6^15^21=28=0x1C
 * g_result = (3<<16)|(42<<8)|28 = 0x00032A1C
 */
#include <stdint.h>

static int count_digit_ones(int n)
{
    int count = 0;
    for (int pos = 1; pos <= n; pos *= 10) {
        int higher  = n / (pos * 10);
        int current = (n / pos) % 10;
        int lower   = n % pos;
        if (current > 1)
            count += (higher + 1) * pos;
        else if (current == 1)
            count += higher * pos + lower + 1;
        else
            count += higher * pos;
    }
    return count;
}

volatile uint32_t g_result;

int main(void)
{
    int r0 = count_digit_ones(13);
    int r1 = count_digit_ones(50);
    int r2 = count_digit_ones(100);

    int sum = r0 + r1 + r2;
    uint32_t xor_res = (uint32_t)(r0 ^ r1 ^ r2);

    g_result = (3u << 16) | ((uint32_t)sum << 8) | (xor_res & 0xFFu);
    /* expected: (3<<16)|(42<<8)|28 = 0x00032A1C */
    return 0;
}
