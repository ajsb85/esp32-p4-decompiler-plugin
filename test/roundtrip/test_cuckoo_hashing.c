/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Cuckoo Hashing fixture.
 *
 * Cuckoo hashing uses two hash tables (T1 and T2) with two independent
 * hash functions.  On collision, the occupying key is "kicked out" to its
 * alternate table.  If evictions loop (cycle detection via MAX_EVICT limit),
 * the table is rehashed.
 *
 * Distinctive decompiler idioms:
 *   1. Dual-table index:  h1(k)=k%CAP, h2(k)=(k/CAP)%CAP
 *   2. Eviction loop:     for(ev=0; ev<MAX_EVICT; ev++) { swap & kick }
 *   3. Cycle sentinel:    if (ev==MAX_EVICT) return REHASH_NEEDED
 *   4. Lookup:            if(T1[h1(k)]==k || T2[h2(k)]==k) found
 *   5. Tombstone value:   0 (empty slot marker, keys are 1-based)
 *
 * Keys inserted: {11, 22, 33, 44, 55, 66, 77, 88}  (n_insert=8)
 * Lookup probes: {11, 33, 55, 77, 99}               (n_probe=5)
 * Expected hits: {11, 33, 55, 77} found = 4 hits
 * Table size CAP=11 (prime to spread keys)
 *
 * Metrics:
 *   n_tests   = 5   (number of lookup probes)
 *   hits      = 4   (0x04)
 *   occ_xor   = (T1 occupancy) XOR (T2 occupancy) = see calculation below
 *               T1 stores keys at h1(k)=k%11: 11->0,22->0(conflict),33->0..
 *               After all inserts: T1_occ + T2_occ = 8 total
 *               occ_xor = 8 ^ 0 = 8... use simpler metric:
 *               sum of all found keys / 11:  (11+33+55+77)/11 = 16 = 0x10
 *
 * g_result = (5<<16)|(4<<8)|0x10 = 0x050410
 */
#include <stdint.h>

volatile uint32_t g_result;

/* ── Cuckoo Hash Table ────────────────────────────────────────────────────── */

#define CUCK_CAP     11    /* capacity of each sub-table (prime) */
#define CUCK_EMPTY    0    /* sentinel: 0 means empty (keys are >= 1) */
#define MAX_EVICT    32    /* eviction limit before rehash signal */

static uint32_t T1[CUCK_CAP];   /* sub-table 1 */
static uint32_t T2[CUCK_CAP];   /* sub-table 2 */

/* Two independent hash functions */
static int h1(uint32_t k) { return (int)(k % CUCK_CAP); }
static int h2(uint32_t k) { return (int)((k / CUCK_CAP) % CUCK_CAP); }

static void cuck_init(void)
{
    for (int i = 0; i < CUCK_CAP; i++) {
        T1[i] = CUCK_EMPTY;
        T2[i] = CUCK_EMPTY;
    }
}

/*
 * cuck_insert: insert key k.
 * Returns 1 on success, 0 if eviction cycle exceeded MAX_EVICT.
 * On each step, try to place k in T1 at h1(k).
 * If occupied, kick the occupant and try to place it in T2 at h2(occupant).
 * Alternate between tables until an empty slot is found or limit hit.
 */
static int cuck_insert(uint32_t k)
{
    if (k == CUCK_EMPTY) return 0;   /* can't insert sentinel */

    for (int ev = 0; ev < MAX_EVICT; ev++) {
        /* Try to place in T1 */
        int i1 = h1(k);
        if (T1[i1] == CUCK_EMPTY) {
            T1[i1] = k;
            return 1;
        }
        /* Kick occupant from T1 */
        uint32_t tmp = T1[i1];
        T1[i1] = k;
        k = tmp;

        /* Try to place kicked key in T2 */
        int i2 = h2(k);
        if (T2[i2] == CUCK_EMPTY) {
            T2[i2] = k;
            return 1;
        }
        /* Kick occupant from T2 */
        tmp = T2[i2];
        T2[i2] = k;
        k = tmp;
    }
    return 0;   /* eviction cycle — caller should rehash */
}

/*
 * cuck_lookup: return 1 if k is in either sub-table.
 */
static int cuck_lookup(uint32_t k)
{
    if (k == CUCK_EMPTY) return 0;
    return (T1[h1(k)] == k) || (T2[h2(k)] == k);
}

/* ── Test ─────────────────────────────────────────────────────────────────── */

#define N_INSERT 8
#define N_PROBE  5

static const uint32_t keys[N_INSERT] = {11, 22, 33, 44, 55, 66, 77, 88};
static const uint32_t probes[N_PROBE] = {11, 33, 55, 77, 99};
/* Expected: 11 found, 33 found, 55 found, 77 found, 99 NOT found => 4 hits */

void test_cuckoo_hashing(void)
{
    cuck_init();

    for (int i = 0; i < N_INSERT; i++) {
        cuck_insert(keys[i]);
    }

    uint32_t hits = 0;
    uint32_t found_sum = 0;
    for (int i = 0; i < N_PROBE; i++) {
        if (cuck_lookup(probes[i])) {
            hits++;
            found_sum += probes[i];
        }
    }
    /* hits=4, found_sum = 11+33+55+77 = 176; 176/11 = 16 = 0x10 */
    uint32_t metric_b = found_sum / CUCK_CAP;   /* 176/11 = 16 = 0x10 */

    g_result = ((uint32_t)N_PROBE << 16) | ((hits & 0xFFu) << 8) | (metric_b & 0xFFu);
    /* expected: 0x050410 */
}

__attribute__((noreturn)) void _start(void)
{
    test_cuckoo_hashing();
    while (1) {}
}
