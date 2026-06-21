/* test_moser_de_bruijn.c
 * Purpose   : Generate Moser-de Bruijn sequence terms
 * Algorithm : The Moser-de Bruijn sequence consists of sums of distinct
 *             powers of 4: numbers whose base-4 representation uses only
 *             digits 0 and 1 (i.e., 0,1,4,5,16,17,20,21,64,65,68,69,...).
 *             To generate: n is in the sequence iff in base 4 all digits <= 1.
 *             Equivalently, spread the bits of n into positions 0,2,4,6,...
 * Input     : first 12 terms (excluding 0): 1,4,5,16,17,20,21,64,65,68,69,80
 *             n_terms = 12
 * Expected  : sum_terms = 430 (1+4+5+16+17+20+21+64+65+68+69+80)
 *             xor_terms = 80 (0x50)  (XOR of all 12 terms)
 * g_result  = (n_terms<<16) | ((sum_terms & 0xFF)<<8) | (xor_terms & 0xFF)
 *           = (12<<16) | (0xAE<<8) | 0x50 = 0x0CAE50
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

/* Check if n is a Moser-de Bruijn number (all base-4 digits are 0 or 1) */
static uint32_t is_mdb(uint32_t n) {
    if (n == 0) return 1;
    while (n > 0) {
        if ((n & 3u) > 1) return 0;  /* base-4 digit > 1 */
        n >>= 2;
    }
    return 1;
}

void _start(void) {
    uint32_t n_terms = 12;
    uint32_t sum_terms = 0;
    uint32_t xor_terms = 0;
    uint32_t found = 0;
    uint32_t i;

    /* Scan integers starting from 1 to collect n_terms Moser-de Bruijn numbers */
    for (i = 1; found < n_terms; i++) {
        if (is_mdb(i)) {
            sum_terms += i;
            xor_terms ^= i;
            found++;
        }
    }

    /* n_terms=12, sum=430=0x1AE, xor=80=0x50 => 0x0CAE50 */
    g_result = (n_terms << 16) | ((sum_terms & 0xFFu) << 8) | (xor_terms & 0xFFu);
    while (1) {}
}
