/* test_binary_carry_sequence.c
 * Purpose   : Compute the binary carry sequence a(n).
 * Algorithm : a(n) = number of trailing 1-bits in the binary representation
 *             of n.  Equivalently, a(n) is the number of carries that occur
 *             when adding 1 to n in binary (each trailing 1 generates one
 *             carry that propagates to the next bit).
 *
 *             Counting trailing 1s:
 *               cnt = 0;  v = n;
 *               while (v & 1) { cnt++; v >>= 1; }
 *
 * Sequence (n = 1..12): 1,0,2,0,1,0,3,0,1,0,2,0
 *
 * n_tests = 12
 * sum     = 1+0+2+0+1+0+3+0+1+0+2+0 = 10  (0x0A)
 * xor_all = 1^0^2^0^1^0^3^0^1^0^2^0 = 2   (0x02)
 *
 * g_result = (n_tests<<16) | (sum<<8) | xor_all
 *          = (12<<16) | (10<<8) | 2
 *          = 0x0C0A02
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define BCS_N 12

/* Return the number of trailing 1-bits in v (= number of carries adding 1) */
static uint32_t trailing_ones(uint32_t v)
{
    uint32_t cnt = 0;
    while (v & 1u) { cnt++; v >>= 1; }
    return cnt;
}

void test_binary_carry_sequence(void)
{
    uint32_t bcs_sum = 0u;
    uint32_t bcs_xor = 0u;
    for (uint32_t i = 1u; i <= (uint32_t)BCS_N; i++) {
        uint32_t a = trailing_ones(i);
        bcs_sum += a;
        bcs_xor ^= a;
    }
    /* bcs_sum=10, bcs_xor=2, BCS_N=12 → 0x0C0A02 */
    g_result = ((uint32_t)BCS_N << 16) | ((bcs_sum & 0xFFu) << 8) | (bcs_xor & 0xFFu);
}

void _start(void)
{
    test_binary_carry_sequence();
    while (1) {}
}
