#include <stdint.h>
#include <string.h>

/* Count subarrays whose sum equals k.
 * Uses prefix-sum + open-addressing hash table in O(n) time.
 * g_result encodes (n_tests, sum_counts, xor_counts). */

#define HSIZE 1024

typedef struct { int key; int cnt; } HEntry;
static HEntry ht[HSIZE];

static void hclear(void) { memset(ht, 0, sizeof(ht)); }

static void hadd(int k, int v) {
    unsigned h = (unsigned)(k + 512) % HSIZE;
    while (ht[h].cnt && ht[h].key != k) h = (h + 1) % HSIZE;
    ht[h].key = k;
    ht[h].cnt += v;
}

static int hget(int k) {
    unsigned h = (unsigned)(k + 512) % HSIZE;
    while (ht[h].cnt && ht[h].key != k) h = (h + 1) % HSIZE;
    return ht[h].cnt;
}

static int count_subarrays(int *a, int n, int k) {
    hclear();
    hadd(0, 1);
    int prefix = 0, count = 0;
    for (int i = 0; i < n; i++) {
        prefix += a[i];
        count += hget(prefix - k);
        hadd(prefix, 1);
    }
    return count;
}

volatile uint32_t g_result;

void test_subarray_sum_k(void) {
    int a1[] = {1, 1, 1};         int r1 = count_subarrays(a1, 3, 2);   /* 2 */
    int a2[] = {1, 2, 3};         int r2 = count_subarrays(a2, 3, 3);   /* 2 */
    int a3[] = {3,4,7,2,-3,1,4,2};int r3 = count_subarrays(a3, 8, 7);  /* 4 */

    uint32_t s = (uint32_t)(r1 + r2 + r3); /* 8 */
    uint32_t x = (uint32_t)(r1 ^ r2 ^ r3); /* 4 */
    g_result = (3u << 16) | (s << 8) | x;  /* 0x00030804 */
}

__attribute__((noreturn)) void _start(void) {
    test_subarray_sum_k();
    for (;;);
}
