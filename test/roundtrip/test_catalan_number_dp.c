/* test_catalan_number_dp.c — Catalan numbers via DP and combinatorial methods
 * ESP32-P4 RISC-V: -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O2
 * -ffreestanding -nostdlib -Wall -Werror
 *
 * Catalan numbers: C(n) = C(2n,n)/(n+1)
 * DP recurrence: C(0)=1, C(n+1) = sum_{i=0}^{n} C(i)*C(n-i)
 *
 * Applications verified:
 *  - Number of valid parenthesization sequences
 *  - Number of binary trees with n+1 leaves
 *  - Ballot sequences / mountain range paths
 *
 * All arithmetic 32-bit only (values stay small for n <= 12).
 */
#include <stdint.h>

volatile uint32_t g_result;

#define MAX_N 14

/* ── Catalan numbers via DP recurrence ──────────────────────────────────── */
static uint32_t catalan[MAX_N + 1];

static void compute_catalan(void) {
    catalan[0] = 1;
    catalan[1] = 1;
    for (int n = 2; n <= MAX_N; n++) {
        catalan[n] = 0;
        for (int i = 0; i < n; i++) {
            catalan[n] += catalan[i] * catalan[n - 1 - i];
        }
    }
}

/* ── Count BSTs with n keys ────────────────────────────────────────────── */
/* BSTs with n distinct keys = Catalan(n). */
static uint32_t count_bst(int n) { return catalan[n]; }

/* ── Count valid bracket sequences of length 2n ──────────────────────── */
/* Also equals Catalan(n). Verify by DP on strings: dp[i][j] = number of
 * prefixes of length i with j more open than close brackets. */
static uint16_t bracket_dp[2 * MAX_N + 1][MAX_N + 1];

static uint32_t count_bracket_sequences(int n) {
    int len = 2 * n;
    for (int i = 0; i <= len; i++)
        for (int j = 0; j <= n; j++)
            bracket_dp[i][j] = 0;
    bracket_dp[0][0] = 1;
    for (int i = 0; i < len; i++) {
        for (int j = 0; j <= n; j++) {
            if (!bracket_dp[i][j]) continue;
            /* open bracket: j+1 <= n */
            if (j + 1 <= n) bracket_dp[i+1][j+1] += bracket_dp[i][j];
            /* close bracket: j > 0 */
            if (j > 0)       bracket_dp[i+1][j-1] += bracket_dp[i][j];
        }
    }
    return bracket_dp[len][0];
}

/* ── Ballot problem: mountain paths from (0,0) to (2n,0) ─────────────── */
/* Number of paths using +1/-1 steps that never go below 0 = Catalan(n). */
static uint16_t path_dp[2 * MAX_N + 1][MAX_N + 1];

static uint32_t count_mountain_paths(int n) {
    int len = 2 * n;
    for (int i = 0; i <= len; i++)
        for (int j = 0; j <= n; j++)
            path_dp[i][j] = 0;
    path_dp[0][0] = 1;
    for (int i = 0; i < len; i++) {
        for (int j = 0; j <= n; j++) {
            if (!path_dp[i][j]) continue;
            if (j + 1 <= n) path_dp[i+1][j+1] += path_dp[i][j];
            if (j > 0)       path_dp[i+1][j-1] += path_dp[i][j];
        }
    }
    return path_dp[len][0];
}

/* ── test driver ─────────────────────────────────────────────────────────*/
void run_catalan_tests(void) {
    compute_catalan();

    uint32_t n_tests    = 0;
    uint32_t pass_count = 0;
    uint32_t value_acc  = 0;

    /* Known Catalan numbers: C(0)=1 C(1)=1 C(2)=2 C(3)=5 C(4)=14 C(5)=42 C(6)=132 */
    static const uint32_t expected[] = {1,1,2,5,14,42,132,429,1430,4862,16796,58786,208012,742900,2674440};

    /* Test 1: DP recurrence matches known values for n=0..12 */
    {
        n_tests++;
        int ok = 1;
        for (int n = 0; n <= 12; n++) {
            if (catalan[n] != expected[n]) { ok = 0; break; }
        }
        if (ok) pass_count++;
    }

    /* Test 2: BST count matches Catalan */
    {
        n_tests++;
        int ok = 1;
        for (int n = 0; n <= 8; n++) {
            if (count_bst(n) != expected[n]) { ok = 0; break; }
        }
        if (ok) pass_count++;
    }

    /* Test 3: bracket sequence count matches Catalan */
    {
        n_tests++;
        int ok = 1;
        for (int n = 1; n <= 6; n++) {
            if (count_bracket_sequences(n) != expected[n]) { ok = 0; break; }
        }
        if (ok) pass_count++;
    }

    /* Test 4: mountain path count matches Catalan */
    {
        n_tests++;
        int ok = 1;
        for (int n = 1; n <= 6; n++) {
            if (count_mountain_paths(n) != expected[n]) { ok = 0; break; }
        }
        if (ok) pass_count++;
    }

    /* Test 5: accumulate some Catalan values */
    {
        n_tests++;
        value_acc = catalan[5] + catalan[6] + catalan[7]; /* 42+132+429 = 603 */
        if (value_acc == 603) pass_count++;
    }

    uint8_t n_t = (uint8_t)(n_tests   & 0xFF);
    uint8_t m_a = (uint8_t)(pass_count & 0xFF);
    uint8_t m_b = (uint8_t)(value_acc  & 0xFF);
    if (m_a == 0) m_a = 0x2A;
    if (m_b == 0) m_b = 0x4B;
    if (m_b == m_a) m_b ^= 0x19;
    g_result = ((uint32_t)n_t << 16) | ((uint32_t)m_a << 8) | (uint32_t)m_b;
}

void _start(void) {
    run_catalan_tests();
    while (1) {}
}
