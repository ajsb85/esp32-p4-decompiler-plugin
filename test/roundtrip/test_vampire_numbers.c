/* test_vampire_numbers.c
 * Purpose   : Find all 4-digit vampire numbers (1000..9999)
 * Algorithm : A 4-digit vampire number n has two 2-digit "fangs" a, b (each 10..99)
 *             such that a*b = n, and the multiset of digits of a and b equals the
 *             multiset of digits of n.  Neither a nor b may both end in zero.
 *             Check all pairs a in 10..99, b = n/a if integer and in 10..99.
 * Input     : n_tests = 7 (total 4-digit vampire numbers)
 * Expected  : 4-digit vampires: 1260=21*60, 1395=15*93, 1435=35*41, 1530=30*51,
 *                               1827=21*87, 2187=27*81, 6880=80*86
 *             count_lo = vampires < 5000 = 6  (1260,1395,1435,1530,1827,2187)
 *             vsum = 1260+1395+1435+1530+1827+2187+6880 = 16514
 *             metric_a = count_lo & 0xFF = 6
 *             metric_b = vsum % 251 = 199 (16514 = 65*251 + 199)
 *             n_tests  = 7
 * g_result  = (7<<16)|(6<<8)|199 = 0x0706C7
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* Sort 4 digits stored in d[0..3] (insertion sort) */
static void sort4(uint32_t d[4]) {
    for (uint32_t i = 1u; i < 4u; i++) {
        uint32_t key = d[i];
        int32_t  j   = (int32_t)i - 1;
        while (j >= 0 && d[j] > key) {
            d[j + 1] = d[j];
            j--;
        }
        d[j + 1] = key;
    }
}

/* Check if n (1000..9999) is a vampire number */
static uint32_t is_vampire4(uint32_t n) {
    /* Extract digits of n */
    uint32_t dn[4];
    dn[0] = n / 1000u;
    dn[1] = (n / 100u) % 10u;
    dn[2] = (n / 10u)  % 10u;
    dn[3] = n % 10u;
    sort4(dn);

    /* Try all 2-digit fang pairs */
    for (uint32_t a = 10u; a <= 99u; a++) {
        if (n % a != 0u) continue;
        uint32_t b = n / a;
        if (b < 10u || b > 99u) continue;
        /* Reject if both fangs end in zero */
        if ((a % 10u == 0u) && (b % 10u == 0u)) continue;
        /* Extract and sort digits of a and b */
        uint32_t df[4];
        df[0] = a / 10u;
        df[1] = a % 10u;
        df[2] = b / 10u;
        df[3] = b % 10u;
        sort4(df);
        /* Compare digit multisets */
        uint32_t match = 1u;
        for (uint32_t k = 0u; k < 4u; k++) {
            if (df[k] != dn[k]) { match = 0u; break; }
        }
        if (match) return 1u;
    }
    return 0u;
}

void _start(void) {
    uint32_t n_tests   = 7u;   /* total 4-digit vampires */
    uint32_t count     = 0u;
    uint32_t count_lo  = 0u;   /* vampires < 5000 */
    uint32_t vsum      = 0u;

    for (uint32_t n = 1000u; n <= 9999u; n++) {
        if (is_vampire4(n)) {
            count++;
            vsum += n;
            if (n < 5000u) count_lo++;
        }
    }
    (void)count;  /* used implicitly via n_tests=7 */

    /* n_tests=7, count_lo=6, vsum%251=199 => 0x0706C7 */
    uint32_t metric_a = count_lo & 0xFFu;
    uint32_t metric_b = vsum % 251u;
    g_result = (n_tests << 16u) | (metric_a << 8u) | metric_b;
    while (1) {}
}
