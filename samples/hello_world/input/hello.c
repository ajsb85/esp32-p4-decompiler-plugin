/* SPDX-License-Identifier: Apache-2.0
 * Bare-metal ESP32-P4 hello world — pure computation, no libc.
 * Designed to survive Ghidra decompilation and recompilation.
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Iterative Fibonacci */
static uint32_t fib(uint32_t n) {
    if (n < 2) return n;
    uint32_t a = 0, b = 1;
    for (uint32_t i = 2; i <= n; i++) {
        uint32_t c = a + b;
        a = b;
        b = c;
    }
    return b;
}

/* Single-byte CRC32 step (polynomial 0x04C11DB7, MSB-first) */
static uint32_t crc32_step(uint32_t crc, uint8_t byte) {
    crc ^= (uint32_t)byte << 24;
    for (int i = 0; i < 8; i++) {
        if (crc & 0x80000000u)
            crc = (crc << 1) ^ 0x04C11DB7u;
        else
            crc <<= 1;
    }
    return crc;
}

/* Combine fib + CRC over 10 iterations */
void hello_world(void) {
    uint32_t acc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < 10; i++) {
        uint32_t f = fib(i);
        acc = crc32_step(acc, (uint8_t)(f & 0xFF));
        acc = crc32_step(acc, (uint8_t)((f >> 8) & 0xFF));
    }
    g_result = acc ^ 0xFFFFFFFFu;
}

/* Entry point */
__attribute__((noreturn)) void _start(void) {
    hello_world();
    for (;;);
}
