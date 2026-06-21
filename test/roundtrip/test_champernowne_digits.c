/* test_champernowne_digits.c
 * Purpose   : Generate the first N digits of the Champernowne sequence C(10)
 * Algorithm : Concatenate integers 1, 2, 3, ... in decimal.
 *             C(10) = 1 2 3 4 5 6 7 8 9 1 0 1 1 1 2 1 3 ...
 *             Extract each digit and accumulate statistics.
 * Input     : first 20 digits of C(10)
 *             = {1,2,3,4,5,6,7,8,9,1,0,1,1,1,2,1,3,1,4,1}
 * Expected  : count_ones = 8 (digit value 1 appears 8 times)
 *             sum_digits = 1+2+3+4+5+6+7+8+9+1+0+1+1+1+2+1+3+1+4+1 = 61
 *             n_digits = 20
 * g_result  = (n_digits<<16) | (count_ones<<8) | (sum_digits & 0xFF)
 *           = (20<<16) | (8<<8) | 61 = 0x14083D
 */
/* xesploop-free: yes */

#include <stdint.h>

volatile uint32_t g_result;

#define CHAMP_N 20

static uint8_t champ_buf[CHAMP_N];

/* Fill champ_buf with the first CHAMP_N digits of the Champernowne sequence */
static void champernowne_fill(void) {
    uint32_t pos = 0;
    uint32_t num = 1;
    /* temporary storage for digits of one integer (max 10 digits for 32-bit) */
    uint8_t tmp[10];
    while (pos < CHAMP_N) {
        /* extract digits of num into tmp, least significant first */
        uint32_t v = num;
        int len = 0;
        do {
            tmp[len++] = (uint8_t)(v % 10);
            v /= 10;
        } while (v > 0);
        /* reverse tmp to get most significant first */
        for (int i = 0, j = len - 1; i < j; i++, j--) {
            uint8_t t = tmp[i]; tmp[i] = tmp[j]; tmp[j] = t;
        }
        /* copy into champ_buf */
        for (int i = 0; i < len && pos < CHAMP_N; i++, pos++) {
            champ_buf[pos] = tmp[i];
        }
        num++;
    }
}

void _start(void) {
    champernowne_fill();

    uint32_t count_ones = 0;
    uint32_t sum_digits = 0;
    for (uint32_t i = 0; i < CHAMP_N; i++) {
        if (champ_buf[i] == 1) count_ones++;
        sum_digits += champ_buf[i];
    }

    /* n_digits=20, count_ones=8, sum_digits=61 => 0x14083D */
    g_result = ((uint32_t)CHAMP_N << 16) | (count_ones << 8) | (sum_digits & 0xFF);
    while (1) {}
}
