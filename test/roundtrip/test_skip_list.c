/*
 * test_skip_list.c — two-level skip list simulation
 *
 * Build a sorted list {2,5,9,12,17,23,31,45} (n=8).
 * Express lane (level-1, every 2nd element): indices 0,2,4,6 → {2,9,17,31}.
 * Base lane: all 8 elements.
 *
 * Searches: find(9)→1, find(23)→1, find(15)→0
 * n_queries=3, found_count=2, xor_found=9^23=30=0x1E
 * g_result = (3<<16)|(2<<8)|30 = 0x0003021E
 */
#include <stdint.h>

#define N_ELEM    8
#define N_QUERIES 3

static const int base[N_ELEM]  = {2,5,9,12,17,23,31,45};
static const int express_idx[] = {0,2,4,6};
#define N_EXPRESS 4

/* Search the base lane from start_idx for target. Return 1 if found. */
static int base_scan(int start_idx, int target)
{
    for (int i = start_idx; i < N_ELEM; i++) {
        if (base[i] == target) return 1;
        if (base[i] > target)  return 0;
    }
    return 0;
}

/* Skip-list search using express lane then base scan. */
static int skip_search(int target)
{
    int prev_base = 0;
    for (int e = 0; e < N_EXPRESS; e++) {
        int idx = express_idx[e];
        if (base[idx] > target) break;
        if (base[idx] == target) return 1;
        prev_base = idx;
    }
    return base_scan(prev_base, target);
}

volatile uint32_t g_result;

int main(void)
{
    static const int queries[N_QUERIES] = {9, 23, 15};
    int found = 0;
    uint32_t xor_found = 0;

    for (int i = 0; i < N_QUERIES; i++) {
        if (skip_search(queries[i])) {
            found++;
            xor_found ^= (uint32_t)queries[i];
        }
    }

    g_result = ((uint32_t)N_QUERIES << 16)
             | ((uint32_t)found      <<  8)
             | (xor_found & 0xFFu);
    /* expected: (3<<16)|(2<<8)|30 = 0x0003021E */
    return 0;
}
