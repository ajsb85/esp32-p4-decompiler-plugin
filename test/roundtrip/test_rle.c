/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Run-Length Encoding round-trip fixture.
 *
 * Exercises a compact in-memory RLE codec:
 *   encode: scan for runs → emit (count, value) byte pairs
 *   decode: expand (count, value) pairs → reconstruct original
 *
 * Input (12 bytes): {1,1, 2,2,2, 3, 1,1,1,1, 4,4}
 * Runs: 2×1, 3×2, 1×3, 4×1, 2×4
 * Encoded (10 bytes): {2,1, 3,2, 1,3, 4,1, 2,4}
 * Decoded (12 bytes): matches input
 *
 * XOR of input bytes: 1^1^2^2^2^3^1^1^1^1^4^4 = 0x01
 *
 * g_result = (encode_len << 16) | (decode_len << 8) | input_xor
 *          = (10 << 16) | (12 << 8) | 0x01 = 0x000A0C01
 */
#include <stdint.h>

volatile uint32_t g_result;

#define RLE_BUFMAX 32

/* rle_encode: write (count,value) pairs into out; return number of bytes written */
static uint32_t rle_encode(const uint8_t *in, uint32_t ilen,
                            uint8_t *out, uint32_t omax)
{
    uint32_t ip = 0, op = 0;
    while (ip < ilen && op + 1 < omax) {
        uint8_t  val   = in[ip];
        uint32_t count = 1;
        while (ip + count < ilen && in[ip + count] == val && count < 255)
            count++;
        out[op++] = (uint8_t)count;
        out[op++] = val;
        ip += count;
    }
    return op;
}

/* rle_decode: expand (count,value) pairs from enc into out; return bytes written */
static uint32_t rle_decode(const uint8_t *enc, uint32_t elen,
                            uint8_t *out, uint32_t omax)
{
    uint32_t ep = 0, op = 0;
    while (ep + 1 < elen && op < omax) {
        uint32_t count = enc[ep++];
        uint8_t  val   = enc[ep++];
        for (uint32_t k = 0; k < count && op < omax; k++)
            out[op++] = val;
    }
    return op;
}

void test_rle(void)
{
    static const uint8_t input[12] = {1,1, 2,2,2, 3, 1,1,1,1, 4,4};
    uint8_t enc_buf[RLE_BUFMAX];
    uint8_t dec_buf[RLE_BUFMAX];

    uint32_t enc_len = rle_encode(input, 12, enc_buf, RLE_BUFMAX);
    uint32_t dec_len = rle_decode(enc_buf, enc_len, dec_buf, RLE_BUFMAX);

    uint32_t input_xor = 0;
    for (uint32_t i = 0; i < 12; i++)
        input_xor ^= input[i];

    g_result = (enc_len << 16) | (dec_len << 8) | (input_xor & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_rle();
    for (;;);
}
