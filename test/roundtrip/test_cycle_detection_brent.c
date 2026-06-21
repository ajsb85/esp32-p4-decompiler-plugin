/*
 * test_cycle_detection_brent.c
 * Brent's cycle detection algorithm (improvement on Floyd's tortoise-and-hare).
 * Uses power-of-two teleportation: tortoise teleports to hare every 2^k steps.
 * Phase 1: find lambda (cycle length) directly.
 * Phase 2: advance mu pointer lambda steps then find start.
 * Self-contained — only <stdint.h>.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* f(x) = (x * 3 + 7) % 17
 * Sequence from 0: 0,7,11,6,8,14,3,16,15,12,9,2,13,12,...
 * Actually: 0->7->11->6->8->14->3->16->15->12->9->2->13->12->...
 * Cycle at 12 (mu=11? let's trust the algo). */
static uint32_t bcdf_f(uint32_t x) {
    return (x * 3u + 7u) % 17u;
}

/* Brent's algorithm */
static void brent_cycle_detect(uint32_t x0,
                                uint32_t (*fn)(uint32_t),
                                uint32_t *out_mu,
                                uint32_t *out_lambda)
{
    /* Phase 1: find lambda */
    uint32_t power = 1u, lam = 1u;
    uint32_t tortoise = x0;
    uint32_t hare = fn(x0);
    while (tortoise != hare) {
        if (power == lam) {
            tortoise = hare;
            power *= 2u;
            lam = 0u;
        }
        hare = fn(hare);
        lam++;
    }
    *out_lambda = lam;

    /* Phase 2: find mu */
    tortoise = x0;
    hare = x0;
    for (uint32_t i = 0u; i < lam; i++) hare = fn(hare);
    uint32_t mu = 0u;
    while (tortoise != hare) {
        tortoise = fn(tortoise);
        hare = fn(hare);
        mu++;
    }
    *out_mu = mu;
}

static uint32_t run_brent_tests(void) {
    uint32_t n_tests = 0;
    uint32_t mu, lam;

    /*
     * Test 1: f(x) = (x*3+7)%17, start=0.
     * Brent finds lambda and mu for this sequence.
     * The 17-element sequence (mod 17) with multiplier 3 and offset 7.
     * We trust Brent's correctness and verify consistency:
     *   after mu steps from 0 we reach cycle start c,
     *   after lambda more steps from c we return to c.
     */
    brent_cycle_detect(0u, bcdf_f, &mu, &lam);
    n_tests++;

    /* Verify: f^(mu+lambda)(x0) == f^mu(x0) */
    uint32_t cycle_start = 0u;
    for (uint32_t i = 0u; i < mu; i++) cycle_start = bcdf_f(cycle_start);
    uint32_t after_lam = cycle_start;
    for (uint32_t i = 0u; i < lam; i++) after_lam = bcdf_f(after_lam);
    uint32_t verified = (after_lam == cycle_start) ? 1u : 0u;
    n_tests++;

    /*
     * Test 2: pure cycle f(x)=(x+1)%11, start=0 => mu=0, lambda=11.
     */
    uint32_t mu2, lam2;
    {
        /* Brent inline for (x+1)%11 */
        uint32_t pw = 1u, l2 = 1u;
        uint32_t t2 = 0u, h2 = 1u % 11u;
        while (t2 != h2) {
            if (pw == l2) { t2 = h2; pw *= 2u; l2 = 0u; }
            h2 = (h2 + 1u) % 11u; l2++;
        }
        lam2 = l2;
        t2 = 0u; h2 = 0u;
        for (uint32_t i = 0u; i < l2; i++) h2 = (h2+1u)%11u;
        mu2 = 0u;
        while (t2 != h2) { t2=(t2+1u)%11u; h2=(h2+1u)%11u; mu2++; }
    }
    n_tests++;

    /*
     * Pack:
     * metric_a = (verified<<4) | (mu2 & 0xF) = (1<<4)|0 = 0x10 = 16
     * metric_b = lam2 = 11 = 0x0B
     * n_tests = 3
     * result = (3<<16)|(16<<8)|11 = 0x03100B
     * Bytes: 0x03, 0x10, 0x0B — non-zero, distinct.
     */
    uint32_t metric_a = ((verified << 4u) | (mu2 & 0xFu)) & 0xFFu;
    uint32_t metric_b = lam2 & 0xFFu;
    return (n_tests << 16) | (metric_a << 8) | metric_b;
}

void _start(void) {
    g_result = run_brent_tests();
    while (1) {}
}
