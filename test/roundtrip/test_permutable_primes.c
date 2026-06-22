/* test_permutable_primes.c
 * Permutable primes (absolute primes): primes that remain prime under every
 * permutation of their decimal digits.
 * Examples up to 200: 2, 3, 5, 7, 11, 13, 17, 31, 37, 71, 73, 79, 97,
 *                     113, 131, 199
 * count=16, sum=889; metric_a=16, metric_b=889%251=136
 * g_result = (199<<16)|(16<<8)|136 = 0x00C71088
 * Bytes: 0xC7=199, 0x10=16, 0x88=136 — non-zero and distinct.
 *
 * Compile: riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
 *          -O2 -ffreestanding -nostdlib -Wall -Werror -o test.elf test_permutable_primes.c
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Simple primality test */
static uint32_t is_prime(uint32_t n)
{
    if (n < 2u) return 0u;
    if (n == 2u) return 1u;
    if ((n & 1u) == 0u) return 0u;
    for (uint32_t i = 3u; i * i <= n; i += 2u) {
        if (n % i == 0u) return 0u;
    }
    return 1u;
}

/* Count decimal digits of n */
static uint32_t num_digits(uint32_t n)
{
    uint32_t d = 0u;
    if (n == 0u) return 1u;
    while (n > 0u) { d++; n /= 10u; }
    return d;
}

/* Extract digit at position pos (0 = least significant) */
static uint32_t get_digit(uint32_t n, uint32_t pos)
{
    for (uint32_t i = 0u; i < pos; i++) n /= 10u;
    return n % 10u;
}

/* Build number from digit array (d[0]=most significant) */
static uint32_t build_num(uint32_t *d, uint32_t len)
{
    uint32_t n = 0u;
    for (uint32_t i = 0u; i < len; i++) {
        n = n * 10u + d[i];
    }
    return n;
}

/* Generate all permutations of digits[0..len-1] and check each is prime.
 * Uses iterative Heap-style via next_permutation on sorted digits. */
static uint32_t all_perms_prime(uint32_t *digits, uint32_t len)
{
    /* Sort digits ascending (simple insertion sort for small len) */
    for (uint32_t i = 1u; i < len; i++) {
        uint32_t key = digits[i];
        uint32_t j = i;
        while (j > 0u && digits[j - 1u] > key) {
            digits[j] = digits[j - 1u];
            j--;
        }
        digits[j] = key;
    }

    /* Iterate through permutations in lexicographic order */
    uint32_t done = 0u;
    while (!done) {
        uint32_t num = build_num(digits, len);
        if (!is_prime(num)) return 0u;

        /* Compute next permutation */
        /* Find largest i such that digits[i] < digits[i+1] */
        uint32_t found = 0u;
        uint32_t pivot = 0u;
        for (uint32_t i = len - 1u; i > 0u; i--) {
            if (digits[i - 1u] < digits[i]) {
                pivot = i - 1u;
                found = 1u;
                break;
            }
        }
        if (!found) {
            done = 1u;
            break;
        }
        /* Find rightmost element > digits[pivot] */
        uint32_t swap_idx = pivot + 1u;
        for (uint32_t i = pivot + 2u; i < len; i++) {
            if (digits[i] > digits[pivot]) swap_idx = i;
        }
        /* Swap pivot and swap_idx */
        uint32_t tmp = digits[pivot];
        digits[pivot] = digits[swap_idx];
        digits[swap_idx] = tmp;
        /* Reverse suffix after pivot */
        uint32_t lo = pivot + 1u, hi = len - 1u;
        while (lo < hi) {
            tmp = digits[lo]; digits[lo] = digits[hi]; digits[hi] = tmp;
            lo++; hi--;
        }
    }
    return 1u;
}

/* n is a permutable prime iff it is prime and all digit permutations are prime */
static uint32_t is_permutable_prime(uint32_t n)
{
    if (!is_prime(n)) return 0u;
    uint32_t len = num_digits(n);
    uint32_t digits[6];   /* max 6-digit numbers; we check up to 200 */
    for (uint32_t i = 0u; i < len; i++) {
        digits[len - 1u - i] = get_digit(n, i);
    }
    return all_perms_prime(digits, len);
}

void _start(void)
{
    /* Search [2..200] for permutable primes */
    uint32_t n_tests  = 199u;
    uint32_t count    = 0u;
    uint32_t psum     = 0u;

    for (uint32_t n = 2u; n <= n_tests + 1u; n++) {
        if (is_permutable_prime(n)) {
            count++;
            psum += n;
        }
    }

    /* In [2..200]: count=16, sum=889
     * metric_a = 16 & 0xFF = 0x10
     * metric_b = 889 % 251  = 136 = 0x88
     * g_result = (199<<16)|(16<<8)|136 = 0x00C71088 */
    uint32_t metric_a = count & 0xFFu;
    uint32_t metric_b = psum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
