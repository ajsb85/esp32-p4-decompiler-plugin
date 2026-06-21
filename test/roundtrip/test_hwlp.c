/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 xesploop hardware loop round-trip fixture.
 *
 * Uses a confirmed esp.lp.setup encoding to implement a counted accumulator
 * loop, exercising the xesploop hardware loop extension without requiring
 * the esp-specific -march flag (all RISC-V cross-compilers can assemble
 * .word directives).
 *
 * Instruction encoding:
 *
 *   0x0052C02B = esp.lp.setup 0, t0, lp_end
 *     bits[31:20] = 5 (op2031)  →  lp_end = inst_next + (5×2) − 2 = inst_next+8
 *     bits[19:15] = 5 (t0)       →  iteration count in t0 at decode time
 *     bits[14:12] = 4             →  funct3=4 (esp.lp.setup)
 *     bits[11:7]  = 0 (zero)      →  loop ID 0
 *     opcode      = 0x2B          →  custom-1
 *
 *   With op2031=5 the body spans 3 instructions (inst_next+0 … inst_next+8):
 *     body[0]: lw  a1, 0(a0)      ← HWLP0_START
 *     body[1]: addi a0, a0, 4
 *     body[2]: add  a2, a2, a1    ← HWLP0_END = lp_end
 *
 * Test sequence (hwlp_loop_sum):
 *   Input : HWLP_ARR = {1,2,3,4,5,6,7,8}, count = 8
 *   Action: hardware loop sums all 8 elements
 *   Result: sum = 1+2+3+4+5+6+7+8 = 36 = 0x24
 *
 *   g_result = (count << 8) | (sum & 0xFF) = (8<<8) | 0x24 = 0x00000824
 *
 * NOTE: Requires ESP32-P4 ECO2 hardware to execute the esp.lp.setup instruction.
 *       This fixture compiles cleanly on any RV32 cross-compiler but produces
 *       an illegal instruction trap on generic RISC-V cores.
 *       CI smoke tests: Phase 3 (gcc compile) runs; Phase 4 (native) is SKIPPED.
 *       Use --flash <port> with run_roundtrip.sh to validate on real hardware.
 */
#include <stdint.h>

volatile uint32_t g_result;

static const uint32_t HWLP_ARR[8] = {1, 2, 3, 4, 5, 6, 7, 8};

/*
 * hwlp_loop_sum — sum count elements of arr using an xesploop hardware loop.
 *
 * The hardware loop setup instruction (0x0052C02B) configures loop0 with:
 *   - HWLP0_COUNT  = t0 (iteration count, passed via t0 register)
 *   - HWLP0_START  = address of body[0] (lw a1, 0(a0))
 *   - HWLP0_END    = address of body[2] (add a2, a2, a1)  ← inst_next+8
 *
 * After each execution of body[2] the hardware decrements HWLP0_COUNT and
 * branches back to body[0] if count > 0.
 */
static uint32_t hwlp_loop_sum(const uint32_t *arr, uint32_t count)
{
    uint32_t result;
    __asm__ volatile (
        "mv   t0, %[cnt]\n\t"        /* t0 = iteration count              */
        "mv   a0, %[p]\n\t"          /* a0 = pointer to arr[0]            */
        "li   a2, 0\n\t"             /* a2 = accumulator = 0              */
        ".word 0x0052C02B\n\t"       /* esp.lp.setup 0, t0, lp_end        */
        "lw   a1, 0(a0)\n\t"         /* [lp_start] a1 = *arr              */
        "addi a0, a0, 4\n\t"         /* arr++                             */
        "add  a2, a2, a1\n\t"        /* [lp_end]   acc += a1             */
        "mv   %[res], a2\n\t"        /* result = acc (after all iters)   */
        : [res] "=r"(result)
        : [cnt] "r"(count), [p] "r"(arr)
        : "a0", "a1", "a2", "t0", "memory"
    );
    return result;
}

void test_hwlp(void)
{
    uint32_t sum   = hwlp_loop_sum(HWLP_ARR, 8);
    uint32_t count = 8;
    g_result = (count << 8) | (sum & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_hwlp();
    for (;;);
}
