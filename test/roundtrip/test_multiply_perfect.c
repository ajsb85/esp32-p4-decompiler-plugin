/* test_multiply_perfect.c
 * Multiply perfect numbers (k-perfect): positive integers n where sigma(n)
 * is an exact multiple of n, i.e. sigma(n) = k*n for some integer k >= 1.
 * k=1 → only n=1 (trivial); k=2 → ordinary perfect numbers (6, 28, 496 …);
 * k=3 → triperfect (120, 672 …).
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_multiply_perfect.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Sum of all divisors of n (sigma function) */
static uint32_t sigma(uint32_t n)
{
    if (n == 0u) return 0u;
    uint32_t s = 0u;
    for (uint32_t d = 1u; d * d <= n; d++) {
        if (n % d == 0u) {
            s += d;
            if (d != n / d) s += n / d;
        }
    }
    return s;
}

/* n is k-perfect if sigma(n) % n == 0 and k = sigma(n)/n >= 2 */
static uint32_t is_multiply_perfect(uint32_t n)
{
    if (n < 2u) return 0u;
    uint32_t s = sigma(n);
    return (s % n == 0u && s / n >= 2u) ? 1u : 0u;
}

void _start(void)
{
    /* Search [2..999] for multiply-perfect numbers */
    uint32_t n_tests = 199u;   /* upper bound byte fits nicely: 0xC7 */
    uint32_t count   = 0u;
    uint32_t msum    = 0u;

    for (uint32_t n = 2u; n <= n_tests + 1u; n++) {
        if (is_multiply_perfect(n)) {
            count++;
            msum += n;
        }
    }

    /* In [2..200]: 6, 28, 120 → count=3, msum=154
     * metric_a = count & 0xFF = 3, metric_b = msum % 251 = 154
     * n_tests=199 → g_result = (199<<16)|(3<<8)|154 = 0x00C7039A
     * All bytes: 0xC7=199, 0x03=3, 0x9A=154 — non-zero and distinct. */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = msum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
