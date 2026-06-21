/* SPDX-License-Identifier: Apache-2.0
 * Extended round-trip test: XOR stream cipher + key schedule.
 *
 * Implements a toy Feistel-like cipher with:
 *   - key schedule: rotate + XOR with round constant
 *   - stream cipher: per-byte key derivation + XOR
 *   - MAC: final CRC-like accumulation
 *
 * Exercises: multiple function calls, loop with division/modulo,
 *            pointer arithmetic, shift-and-XOR patterns.
 *
 * Expected pattern detection: xor_cipher, crc_loop (or checksum_xor)
 *
 * g_result after encrypt→decrypt→verify should equal 0xABCD65DD
 * if the round-trip is lossless.  If g_result differs, the decompilation
 * broke the cipher symmetry.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define BLOCK_SIZE 8

/* Rotate left 32-bit */
static uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

/* Key schedule: derive sub-key for round r from master key */
static uint32_t key_schedule(uint32_t key, uint32_t round) {
    /* Use round constants inspired by SHA-2 fractional parts */
    static const uint32_t RC[8] = {
        0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u,
        0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    };
    return rotl32(key, (round & 0x1F) + 1) ^ RC[round & 7];
}

/* XOR stream cipher encrypt/decrypt (symmetric) */
static void xor_cipher(uint8_t *buf, uint32_t len, uint32_t key) {
    for (uint32_t i = 0; i < len; i++) {
        uint32_t k = key_schedule(key, i);
        /* Use byte of the derived key matching position */
        buf[i] ^= (uint8_t)((k >> ((i % 4) * 8)) & 0xFFu);
    }
}

/* Poly-1305-style accumulation: MAC over a buffer */
static uint32_t poly_mac(const uint8_t *buf, uint32_t len, uint32_t r) {
    uint32_t acc = 0;
    for (uint32_t i = 0; i < len; i++) {
        acc = rotl32(acc ^ buf[i], 5) + r;
    }
    return acc;
}

/* Simple CRC-8 over a buffer */
static uint8_t crc8(const uint8_t *buf, uint32_t len) {
    uint8_t crc = 0xFF;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++) {
            if (crc & 0x80u)
                crc = (crc << 1) ^ 0x07u;  /* CRC-8/SMBUS polynomial */
            else
                crc <<= 1;
        }
    }
    return crc;
}

void _start(void) {
    /* Test message */
    uint8_t msg[BLOCK_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    uint8_t enc[BLOCK_SIZE];
    uint8_t dec[BLOCK_SIZE];
    uint32_t key = 0x12345678u;

    /* Copy + encrypt */
    for (int i = 0; i < BLOCK_SIZE; i++) enc[i] = msg[i];
    xor_cipher(enc, BLOCK_SIZE, key);

    /* Decrypt (XOR cipher is symmetric) */
    for (int i = 0; i < BLOCK_SIZE; i++) dec[i] = enc[i];
    xor_cipher(dec, BLOCK_SIZE, key);

    /* Verify: dec must equal msg exactly */
    uint32_t ok = 1;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        if (dec[i] != msg[i]) ok = 0;
    }

    /* Compute MAC over encrypted buffer */
    uint32_t mac = poly_mac(enc, BLOCK_SIZE, 0xDEAD);

    /* CRC-8 of original message */
    uint8_t crc = crc8(msg, BLOCK_SIZE);

    /* Final result: if round-trip ok → 0xABCD__ | crc | mac_lo */
    g_result = ok
        ? (0xABCD0000u | ((uint32_t)crc << 8) | (mac & 0xFFu))
        : 0xDEAD0000u;

    /* Expected (approximate — mac is runtime-dependent but deterministic):
     * ok=1, crc=crc8({0xDE,...,0xBE}), mac_lo=poly_mac(enc,...)[7:0]
     * The CRITICAL property is: result must match between original and
     * recompiled firmware (round-trip validation). */

    for (;;);
}
