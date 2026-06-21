/*
 * test_pascals_row.c — compute row n of Pascal's Triangle in-place.
 *
 * row[0]=1; for each of n updates: for j=i downto 1: row[j]+=row[j-1]
 * After n=7 updates: row = {1,7,21,35,35,21,7,1}
 * sum = 2^7 = 128, row[3] = C(7,3) = 35
 *
 * n=7 (row index), sum=128=0x80, row[3]=35=0x23
 * g_result = (7<<16)|(128<<8)|35 = 0x00078023
 */
#include <stdint.h>

#define ROW_CAP 16

volatile uint32_t g_result;

int main(void)
{
    int row[ROW_CAP];
    int n = 7;
    for (int i = 0; i < ROW_CAP; i++) row[i] = 0;
    row[0] = 1;

    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j >= 1; j--)
            row[j] += row[j-1];
    }

    int sum = 0;
    for (int j = 0; j <= n; j++) sum += row[j];

    g_result = ((uint32_t)n        << 16)
             | ((uint32_t)sum       <<  8)
             | ((uint32_t)row[3] & 0xFFu);
    /* expected: (7<<16)|(128<<8)|35 = 0x00078023 */
    return 0;
}
