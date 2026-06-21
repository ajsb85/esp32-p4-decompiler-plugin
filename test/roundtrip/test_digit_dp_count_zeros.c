/* test_digit_dp_count_zeros.c
 * Purpose   : Count integers in [1..100] whose decimal representation
 *             contains at least one zero digit, using digit DP
 * Algorithm : Digit DP with memoized state (position, tight, has_zero).
 *             State tracks whether we are still bounded by the upper limit
 *             (tight constraint) and whether a zero digit has appeared.
 * Input     : upper = 100, n_tests = 100
 * Expected  : Numbers with a zero digit in [1..100]:
 *               10,20,30,40,50,60,70,80,90,100 → count = 10
 *             Sum of those numbers = 10+20+...+90+100 = 550
 *             sum_mod = 550 mod 256 = 38 = 0x26
 *             n_tests = 100 = 0x64
 * g_result  = (n_tests<<16) | (count<<8) | sum_mod
 *           = (100<<16) | (10<<8) | 38
 *           = 0x640A26
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* Extract decimal digits of n into digits[], return digit count (MSD first) */
static uint32_t extract_digits(uint32_t n, uint32_t digits[10]) {
    if (n == 0u) { digits[0] = 0u; return 1u; }
    uint32_t tmp = n;
    uint32_t len = 0u;
    uint32_t buf[10];
    while (tmp > 0u) {
        buf[len++] = tmp % 10u;
        tmp /= 10u;
    }
    /* reverse */
    uint32_t i;
    for (i = 0u; i < len; i++) digits[i] = buf[len - 1u - i];
    return len;
}

/* Digit DP memo table: [pos 0..3][tight 0..1][has_zero 0..1] = count */
static uint32_t dp_count[4][2][2];
/* Digit DP sum table: same shape, stores sum contribution */
static uint32_t dp_sum[4][2][2];
static uint32_t g_digits[10];
static uint32_t g_len;

/* Returns: populates dp_count and dp_sum for each state.
 * We solve count of numbers with a zero in [0..N] via digit DP. */
static void digit_dp_solve(uint32_t pos, uint32_t tight, uint32_t has_zero,
                            uint32_t num_so_far) {
    uint32_t limit = tight ? g_digits[pos] : 9u;
    uint32_t d;
    for (d = 0u; d <= limit; d++) {
        uint32_t new_tight = tight && (d == limit) ? 1u : 0u;
        uint32_t new_has_zero = (has_zero || d == 0u) ? 1u : 0u;
        uint32_t new_num = num_so_far * 10u + d;
        if (pos + 1u == g_len) {
            /* leaf: record if this number has a zero digit */
            if (new_has_zero && new_num > 0u) {
                dp_count[pos][tight][has_zero]++;
                dp_sum[pos][tight][has_zero] += new_num;
            }
        } else {
            digit_dp_solve(pos + 1u, new_tight, new_has_zero, new_num);
        }
    }
}

void _start(void) {
    uint32_t upper = 100u;
    uint32_t n_tests = upper;

    /* Reset DP tables */
    uint32_t i, j, k;
    for (i = 0u; i < 4u; i++)
        for (j = 0u; j < 2u; j++)
            for (k = 0u; k < 2u; k++) {
                dp_count[i][j][k] = 0u;
                dp_sum[i][j][k] = 0u;
            }

    g_len = extract_digits(upper, g_digits);
    digit_dp_solve(0u, 1u, 0u, 0u);

    /* Sum up all states */
    uint32_t total_count = 0u;
    uint32_t total_sum = 0u;
    for (i = 0u; i < 4u; i++)
        for (j = 0u; j < 2u; j++)
            for (k = 0u; k < 2u; k++) {
                total_count += dp_count[i][j][k];
                total_sum += dp_sum[i][j][k];
            }

    uint32_t sum_mod = total_sum & 0xFFu;  /* mod 256 */

    /* n_tests=100=0x64, count=10=0x0A, sum_mod=38=0x26 => 0x640A26 */
    g_result = (n_tests << 16) | (total_count << 8) | sum_mod;
    while (1) {}
}
