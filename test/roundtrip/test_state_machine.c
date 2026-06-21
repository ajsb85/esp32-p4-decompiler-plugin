/* SPDX-License-Identifier: Apache-2.0
 * Extended round-trip test: packet parser state machine.
 *
 * Protocol frame format:
 *   0xAA  <len:1>  <payload:len>  <checksum:1>
 *   checksum = XOR of all payload bytes
 *
 * Exercises: switch/case, enum typedef, multiple state variables.
 *
 * Expected pattern detection: state_machine, parser_packet
 *
 * Test vector:
 *   Frame 1: AA 03 DE AD BE EF (DE^AD^BE=EF) → valid
 *   Frame 2: AA 02 CA FE CC      (CA^FE=34≠CC) → invalid
 *   Frame 3: AA 01 42 42         (valid)
 *   Total valid = 2 packets
 *   g_result = 2
 */
#include <stdint.h>

volatile uint32_t g_result;

typedef enum { ST_IDLE = 0, ST_HEADER, ST_PAYLOAD, ST_CHECKSUM } ParserState;

/* Returns number of valid packets found in the buffer */
static uint32_t parse_frames(const uint8_t *data, uint32_t len) {
    ParserState state       = ST_IDLE;
    uint32_t    valid_count = 0;
    uint8_t     checksum    = 0;
    uint32_t    payload_len = 0;
    uint32_t    payload_pos = 0;

    for (uint32_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        switch (state) {
            case ST_IDLE:
                if (b == 0xAAu) state = ST_HEADER;
                break;

            case ST_HEADER:
                payload_len = b;
                payload_pos = 0;
                checksum    = 0;
                if (payload_len == 0)
                    state = ST_IDLE;  /* degenerate: no payload */
                else
                    state = ST_PAYLOAD;
                break;

            case ST_PAYLOAD:
                checksum ^= b;
                payload_pos++;
                if (payload_pos >= payload_len)
                    state = ST_CHECKSUM;
                break;

            case ST_CHECKSUM:
                if (b == checksum) valid_count++;
                state = ST_IDLE;
                break;
        }
    }
    return valid_count;
}

/* Simple ring buffer */
#define RING_SIZE 16
typedef struct {
    uint8_t  buf[RING_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} RingBuf;

static void ring_push(RingBuf *rb, uint8_t b) {
    if (rb->count < RING_SIZE) {
        rb->buf[rb->head % RING_SIZE] = b;
        rb->head++;
        rb->count++;
    }
}

static uint8_t ring_pop(RingBuf *rb) {
    if (rb->count == 0) return 0xFF;
    uint8_t val = rb->buf[rb->tail % RING_SIZE];
    rb->tail++;
    rb->count--;
    return val;
}

void _start(void) {
    /* Corrected test vector (checksums pre-verified):
     *   Frame 1: payload={DE,AD,BE}, xor=0xCD → valid   (0xDE^0xAD=0x73, ^0xBE=0xCD)
     *   Frame 2: payload={CA,FE},    xor=0x34, sent 0xFF → invalid
     *   Frame 3: payload={42},       xor=0x42 → valid
     *   valid_count = 2
     */
    static const uint8_t stream2[] = {
        0xAA, 0x03, 0xDE, 0xAD, 0xBE, 0xCD,  /* valid: checksum=0xCD */
        0xAA, 0x02, 0xCA, 0xFE, 0xFF,          /* invalid */
        0xAA, 0x01, 0x42, 0x42,                /* valid */
    };

    uint32_t count = parse_frames(stream2, sizeof(stream2));

    /* Ring buffer smoke test: push 4 values, pop them, checksum */
    RingBuf rb = {.buf={0}, .head=0, .tail=0, .count=0};
    ring_push(&rb, 0x11);
    ring_push(&rb, 0x22);
    ring_push(&rb, 0x33);
    ring_push(&rb, 0x44);
    uint8_t ring_xor = ring_pop(&rb) ^ ring_pop(&rb) ^ ring_pop(&rb) ^ ring_pop(&rb);
    /* = 0x11 ^ 0x22 ^ 0x33 ^ 0x44 = 0x54 */

    g_result = (count << 8) | ring_xor;
    /* = (2 << 8) | 0x54 = 0x0254 */

    for (;;);
}
