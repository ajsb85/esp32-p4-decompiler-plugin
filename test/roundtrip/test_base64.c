/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Base64 encoding round-trip fixture.
 *
 * Implements standard Base64 encoding (RFC 4648) without padding
 * (input length is a multiple of 3).  Exercises bit-shift extraction of
 * 6-bit groups and character table lookup — both highly recognisable
 * patterns after Ghidra decompilation.
 *
 * Input : "Hello!" = {0x48,0x65,0x6C,0x6C,0x6F,0x21} (6 bytes)
 *
 * Base64 encoding of "Hello!":
 *   Group 1: H(48) e(65) l(6C)  →  S G V s
 *   Group 2: l(6C) o(6F) !(21)  →  b G 8 h
 *   Encoded: "SGVsbG8h" (8 bytes)
 *
 * XOR of encoded output:
 *   0x53^0x47^0x56^0x73^0x62^0x47^0x38^0x68 = 0x44
 *
 * g_result = (enc_len << 8) | xor_encoded = (8 << 8) | 0x44 = 0x00000844
 */
#include <stdint.h>

volatile uint32_t g_result;

static const char B64_TABLE[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * base64_encode: encode ilen input bytes into out (must hold ceil(ilen/3)*4 bytes).
 * No padding emitted (caller ensures ilen % 3 == 0 for this fixture).
 * Returns number of bytes written.
 */
static uint32_t base64_encode(const uint8_t *in, uint32_t ilen, char *out)
{
    uint32_t ip = 0, op = 0;
    while (ip + 2 < ilen) {
        unsigned b0 = in[ip];
        unsigned b1 = in[ip + 1];
        unsigned b2 = in[ip + 2];
        out[op++] = B64_TABLE[(b0 >> 2) & 0x3Fu];
        out[op++] = B64_TABLE[((b0 << 4) | (b1 >> 4)) & 0x3Fu];
        out[op++] = B64_TABLE[((b1 << 2) | (b2 >> 6)) & 0x3Fu];
        out[op++] = B64_TABLE[b2 & 0x3Fu];
        ip += 3;
    }
    return op;
}

void test_base64(void)
{
    static const uint8_t input[6] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21};
    char enc_buf[16];

    uint32_t enc_len = base64_encode(input, 6, enc_buf);

    uint32_t xor_enc = 0;
    for (uint32_t i = 0; i < enc_len; i++)
        xor_enc ^= (uint8_t)enc_buf[i];

    g_result = (enc_len << 8) | (xor_enc & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_base64();
    for (;;);
}
