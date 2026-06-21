/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Circular Buffer (Ring Buffer) fixture.
 *
 * Circular buffer with fixed capacity=5 using head/tail pointers.
 * Operations: push to back (tail), pop from front (head), wrap via modulo.
 *
 * Distinctive decompiler idioms:
 *   1. `buf[tail] = v; tail = (tail+1) % cap` — push with wrap
 *   2. `val = buf[head]; head = (head+1) % cap` — pop with wrap
 *   3. `cnt` tracks occupancy; full: cnt==cap; empty: cnt==0
 *
 * Operations:
 *   push 1,2,3,4,5,6 (6 pushes; pop 1 before 6, so 6 wraps)
 *   pop → 1; push 6; pop → 2,3; peek front → 4; size → 3
 *   xor of all 6 pushed values: 1^2^3^4^5^6=7
 *
 * g_result = ((n_pushes+1)<<16)|(front_val<<8)|(xor_pushed&0xFF) = 0x00070407
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_circular_buffer(void)
{
    int cap = 5;
    int buf[5], head = 0, tail = 0, cnt = 0;
    int n_pushes = 0;
    uint32_t xpush = 0u;

    /* Push 1..5 */
    int v;
    for (v = 1; v <= 5; v++) {
        buf[tail] = v; tail = (tail + 1) % cap; cnt++;
        n_pushes++; xpush ^= (uint32_t)v;
    }
    /* Pop front → 1 */
    head = (head + 1) % cap; cnt--;
    /* Push 6 (wraps around: tail was 0, now 1) */
    buf[tail] = 6; tail = (tail + 1) % cap; cnt++;
    n_pushes++; xpush ^= 6u;
    /* Pop front → 2, then → 3 */
    head = (head + 1) % cap; cnt--;
    head = (head + 1) % cap; cnt--;
    /* Peek front: buf[head] = 4 */
    int front_val = buf[head];
    /* size=3 */

    /* n_pushes=6, front_val=4, xpush=7 */
    g_result = ((uint32_t)(n_pushes + 1) << 16)
             | ((uint32_t)front_val << 8)
             | (xpush & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_circular_buffer();
    for (;;);
}
